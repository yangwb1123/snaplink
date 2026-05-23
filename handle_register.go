package sso

import "github.com/snaplink/sso/oauth"

import (
	"crypto/subtle"
	"net/http"
	"slices"
	"strings"
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
// Echoes every accepted metadata field plus the issued credentials,
// timestamps, and the RFC 7592 management URI / access token when
// the management endpoint is enabled.
type dcrResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
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
	// DCR responses ship client_secret + registration_access_token —
	// credential-shaped bodies that intermediaries must not cache.
	// Same RFC 6749 §5.1 pattern as /token.
	tokenNoStoreHeaders(ctx)
	if s.dcrPolicy == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(oauth.ErrRegistrationDisabled))
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
			setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "Initial access token missing or invalid")
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
			return
		}
	}

	var req dcrRequest
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(oauth.ErrInvalidClientMetadata, err.Error()))
		return
	}

	if err := validateDCRMetadata(&req, s.dcrPolicy); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(oauth.ErrInvalidClientMetadata, err.Error()))
		return
	}

	id, err := oauth.GenerateClientID()
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
		secret, err = oauth.GenerateClientSecret()
		if err != nil {
			s.logger.Error("dcr secret gen failed", "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
	}

	// RFC 7592 §3: every newly-registered client gets a
	// registration_access_token so the client itself can later
	// GET/PUT/DELETE its own registration without operator
	// involvement. The token is bearer-shaped; deployments
	// storing clients on disk SHOULD hash it at rest.
	regToken, err := oauth.GenerateClientSecret()
	if err != nil {
		s.logger.Error("dcr reg-token gen failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	tokenStrategy := req.TokenStrategy
	if tokenStrategy == "" {
		tokenStrategy = s.dcrPolicy.DefaultTokenStrategy
	}

	client := &Client{
		ID:                      id,
		Secret:                  secret,
		Name:                    req.ClientName,
		RedirectURIs:            append([]string(nil), req.RedirectURIs...),
		AllowedScopes:           splitScope(req.Scope),
		AllowedAuthenticators:   append([]string(nil), req.AllowedAuthenticators...),
		TokenStrategy:           tokenStrategy,
		Active:                  s.dcrPolicy.DefaultActive,
		TenantID:                req.TenantID,
		RequirePKCE:             req.RequirePKCE || public, // public clients always PKCE
		AllowedResources:        append([]string(nil), req.AllowedResources...),
		PostLogoutRedirectURIs:  append([]string(nil), req.PostLogoutRedirectURIs...),
		RegistrationAccessToken: regToken,
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
		RegistrationAccessToken: regToken,
		RegistrationClientURI:   requestBaseURL(ctx.Request()) + oauth.PathRegister + "/" + id,
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

// handleRegistrationGet implements RFC 7592 §2.1 — the client
// itself reads its current registration metadata. Auth: bearer
// matching the registration_access_token issued at /register.
func (s *Server) handleRegistrationGet(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	client, ok := s.authorizeRegistrationMgmt(ctx)
	if !ok {
		return
	}
	ctx.JSON(http.StatusOK, projectClientToDCRResponse(client, ctx))
}

// handleRegistrationPut implements RFC 7592 §2.2 — the client
// itself updates its metadata. Auth: bearer matching the
// registration_access_token. Validation: same rules as POST
// /register; the client_secret stays unchanged across updates
// (rotation is a separate admin RPC). The registration_access_token
// is also preserved so the caller can keep managing the registration.
func (s *Server) handleRegistrationPut(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	client, ok := s.authorizeRegistrationMgmt(ctx)
	if !ok {
		return
	}

	var req dcrRequest
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(oauth.ErrInvalidClientMetadata, err.Error()))
		return
	}
	if err := validateDCRMetadata(&req, s.dcrPolicy); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(oauth.ErrInvalidClientMetadata, err.Error()))
		return
	}

	tokenStrategy := req.TokenStrategy
	if tokenStrategy == "" {
		tokenStrategy = client.TokenStrategy
	}

	updated := &Client{
		ID:                      client.ID,
		Secret:                  client.Secret,                  // unchanged
		RegistrationAccessToken: client.RegistrationAccessToken, // unchanged
		Active:                  client.Active,
		Name:                    req.ClientName,
		RedirectURIs:            append([]string(nil), req.RedirectURIs...),
		AllowedScopes:           splitScope(req.Scope),
		AllowedAuthenticators:   append([]string(nil), req.AllowedAuthenticators...),
		TokenStrategy:           tokenStrategy,
		TenantID:                req.TenantID,
		RequirePKCE:             req.RequirePKCE || req.TokenEndpointAuthMethod == "none",
		AllowedResources:        append([]string(nil), req.AllowedResources...),
		PostLogoutRedirectURIs:  append([]string(nil), req.PostLogoutRedirectURIs...),
	}

	if err := s.clientStore.Update(ctx.Request().Context(), updated); err != nil {
		s.logger.Error("dcr update failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, projectClientToDCRResponse(updated, ctx))
}

// handleRegistrationDelete implements RFC 7592 §2.3 — the client
// itself removes its registration. Auth: bearer matching the
// registration_access_token. Successful response: 204 No Content
// per §2.3.
func (s *Server) handleRegistrationDelete(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	client, ok := s.authorizeRegistrationMgmt(ctx)
	if !ok {
		return
	}
	if err := s.clientStore.Delete(ctx.Request().Context(), client.ID); err != nil {
		s.logger.Error("dcr delete failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	ctx.ResponseWriter().WriteHeader(http.StatusNoContent)
}

// authorizeRegistrationMgmt is the shared auth + lookup gate for
// every RFC 7592 endpoint. Resolves the client by path param,
// constant-time compares the presented bearer against the stored
// registration_access_token, and writes the appropriate error
// response when checks fail.
//
// Returns (client, true) on success; on failure it has already
// written the response and returns (nil, false).
func (s *Server) authorizeRegistrationMgmt(ctx HandlerContext) (*Client, bool) {
	if s.dcrPolicy == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(oauth.ErrRegistrationDisabled))
		return nil, false
	}
	if err := s.requireDeps(depClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return nil, false
	}
	id := ctx.Param("client_id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrMissingClientID))
		return nil, false
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), id)
	if err != nil {
		// 401 (not 404) because the resource is auth-gated; a 404
		// would let an unauthed caller probe for client_id existence.
		// The challenge stays identical across "unknown client",
		// "missing bearer", and "wrong bearer" to preserve the
		// anti-enumeration property the catch-all 401 enforces.
		setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "Registration access token missing or invalid")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return nil, false
	}
	bearer := bearerToken(ctx.Request())
	if bearer == "" || client.RegistrationAccessToken == "" {
		setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "Registration access token missing or invalid")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return nil, false
	}
	if subtleConstantTimeStringEq(bearer, client.RegistrationAccessToken) != 1 {
		setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "Registration access token missing or invalid")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return nil, false
	}
	return client, true
}

// projectClientToDCRResponse builds an RFC 7591-shaped response from
// a stored Client. Re-used by GET/PUT — the registration_access_token
// is NOT re-emitted (RFC 7592 §2.1: server SHOULD NOT include it on
// reads; the original /register response is the only canonical
// distribution point).
func projectClientToDCRResponse(c *Client, ctx HandlerContext) dcrResponse {
	return dcrResponse{
		ClientID:               c.ID,
		ClientSecret:           c.Secret, // RFC 7592 §2.1 SHOULD include
		ClientSecretExpiresAt:  0,
		RegistrationClientURI:  requestBaseURL(ctx.Request()) + oauth.PathRegister + "/" + c.ID,
		RedirectURIs:           c.RedirectURIs,
		ClientName:             c.Name,
		Scope:                  joinScope(c.AllowedScopes),
		TokenStrategy:          c.TokenStrategy,
		AllowedAuthenticators:  c.AllowedAuthenticators,
		AllowedResources:       c.AllowedResources,
		PostLogoutRedirectURIs: c.PostLogoutRedirectURIs,
		RequirePKCE:            c.RequirePKCE,
	}
}

func joinScope(scopes []string) string {
	return strings.Join(scopes, " ")
}

// subtleConstantTimeStringEq wraps subtle.ConstantTimeCompare for
// strings — it short-circuits on length mismatch (the standard
// library function does too, but we keep the wrapper local so the
// length check is explicit and reviewable).
func subtleConstantTimeStringEq(a, b string) int {
	if len(a) != len(b) {
		return 0
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}

// validateDCRMetadata enforces the subset of RFC 7591 §2 / §5
// rules this server understands plus the policy's whitelist
// constraints.
func validateDCRMetadata(req *dcrRequest, policy *oauth.DCRPolicy) error {
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
