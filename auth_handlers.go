package sso

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/spi"
)

// handleEndSession implements OpenID Connect RP-Initiated Logout 1.0.
// Unlike POST /logout (a session-scoped bearer-authenticated kill
// switch), this is a GET endpoint a relying party can redirect the
// user agent to so the SSO server logs the user out and then sends
// them back to the RP's post-logout page.
//
// Query parameters (per the spec §2):
//
//   - id_token_hint            REQUIRED to identify the user — a
//     previously-issued id_token. The server
//     validates the signature and uses the
//     token's aud claim to look up the client.
//   - post_logout_redirect_uri Optional; MUST be in the client's
//     PostLogoutRedirectURIs allowlist.
//   - state                    Optional; echoed back on the redirect.
//   - client_id                Optional fallback when id_token_hint
//     is absent — used only for
//     redirect-uri allowlist lookup, NOT
//     for session termination.
//
// Behavior:
//
//   - Always best-effort revokes the access token derived from the
//     id_token_hint (so a stolen id_token_hint can't be used to
//     just bounce the user without invalidating their session).
//   - When post_logout_redirect_uri is in the allowlist, returns
//     302 with Location pointing at the redirect_uri (+ state when
//     supplied).
//   - When the redirect_uri is missing or rejected, returns 204 —
//     the session is dead, but we don't open a redirect-vector for
//     callers without a registered URL.
//
// Security:
//
//   - id_token_hint signature MUST verify against the server's
//     wired token issuers (we treat ID tokens and access tokens
//     as signed by the same key pair).
//   - post_logout_redirect_uri MUST exact-match (no path tolerance,
//     no scheme-only match) — phishing defense per §3.
func (s *Server) handleEndSession(ctx HandlerContext) {
	q := ctx.Request().URL.Query()
	idTokenHint := strings.TrimSpace(q.Get("id_token_hint"))
	postLogoutURI := strings.TrimSpace(q.Get("post_logout_redirect_uri"))
	state := q.Get("state")
	clientIDHint := strings.TrimSpace(q.Get("client_id"))

	var (
		client *Client
		userID string
		sid    string
	)

	if idTokenHint != "" {
		// Best-effort verification: an id_token_hint with a bad
		// signature is a phishing attempt; we MUST not honor any
		// post_logout_redirect_uri tied to its claimed audience.
		claims, _, err := s.validateAnyToken(ctx.Request().Context(), idTokenHint)
		if err != nil || claims == nil {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidToken))
			return
		}
		userID = claims.Subject
		// OIDC §8 pairwise: translate the per-sector sub back to the
		// local one so downstream session bookkeeping finds the
		// right user. Non-pairwise deployments no-op.
		if local, perr := s.resolveLocalSubject(ctx.Request().Context(), userID); perr == nil {
			userID = local
		}
		sid = claims.SID
		// Resolve the client by RFC 9068 client_id claim (preferred,
		// first-class) or fall back to the first audience entry (the
		// pre-9068 heuristic) — matches handleLogout's lookup so
		// behavior is consistent across the two logout endpoints.
		clientLookupID := claims.ClientID
		if clientLookupID == "" && len(claims.Audience) > 0 {
			clientLookupID = claims.Audience[0]
		}
		if clientLookupID != "" && s.clientStore != nil {
			if c, err := s.clientStore.Get(ctx.Request().Context(), clientLookupID); err == nil {
				client = c
			}
		}
	} else if clientIDHint != "" && s.clientStore != nil {
		// Spec allows client_id without id_token_hint, but without
		// a signed user identity we won't revoke any session — we
		// only use the client to validate the redirect uri.
		if c, err := s.clientStore.Get(ctx.Request().Context(), clientIDHint); err == nil {
			client = c
		}
	}

	// Kill the presented id_token's access-side counterpart so a
	// stolen id_token_hint can't be used as a soft-logout that
	// leaves the access token alive until expiry.
	if idTokenHint != "" {
		revoked, failed := s.revokeAcrossIssuers(ctx.Request().Context(), idTokenHint)
		s.auditPartialRevokeFailure(ctx, revoked, failed)
	}
	// Wipe every refresh token the user holds for the client in
	// scope, so descendant rotations can't outlive the logout.
	if userID != "" && client != nil {
		if idx, ok := s.refreshTokenStore.(oauth.RefreshTokenSubjectIndex); ok {
			_, _ = idx.DeleteAllForSubject(ctx.Request().Context(), userID, client.ID)
		}
	}

	// Capture FCL fan-out targets BEFORE the BCL fan-out runs.
	// BCL's Forget-on-non-BCL behavior trims the security.SubjectClientIndex
	// of clients without a BackchannelLogoutURI; if FCL gathered
	// AFTER, those FCL-only peers would be missing from the index
	// by the time we walked it and silently dropped from the
	// iframe list. Render happens later — this just snapshots the
	// targets while the index is still complete.
	var fclIframes []string
	if userID != "" {
		fclIframes = s.gatherFrontchannelLogoutIframes(ctx, userID, client, sid)
	}

	// OIDC Back-Channel Logout 1.0 — mirror of the /logout
	// behavior. When the user logs out via the redirect-style
	// /end_session, the RP whose id_token_hint was presented
	// should also be notified via back-channel so its local
	// session can be torn down. No-op when BCL isn't wired or
	// the client doesn't declare a backchannel_logout_uri.
	if userID != "" && client != nil {
		s.fanOutBackchannelLogout(ctx, client, userID, sid)
	}

	if userID != "" {
		s.recordLogout(ctx, "", []string{"id_token_hint"})
	}

	// Resolve a safe redirect destination once — both the FCL HTML
	// page and the legacy 302 path want the same allowlist + state
	// composition; computing it in one place keeps phishing defense
	// uniform across the two response shapes.
	var target string
	if postLogoutURI != "" && client != nil && client.IsPostLogoutRedirectURIValid(postLogoutURI) {
		target = postLogoutURI
		if state != "" {
			sep := "?"
			if strings.Contains(target, "?") {
				sep = "&"
			}
			target = target + sep + "state=" + url.QueryEscape(state)
		}
	}

	// OIDC Front-Channel Logout 1.0 — when any client (the primary
	// from id_token_hint, or any other the subject is signed into
	// via the security.SubjectClientIndex) opts in via FrontchannelLogoutURI,
	// render an HTML page with one hidden iframe per such client.
	// The browser fires each iframe request (clearing RP cookies);
	// a meta-refresh then navigates to post_logout_redirect_uri if
	// one was allowlisted. FCL is purely additive to the
	// revoke/BCL pipeline above — those still ran. Iframe targets
	// were snapshotted above before BCL pruned the index.
	if len(fclIframes) > 0 {
		s.renderFrontchannelLogout(ctx, fclIframes, target)
		return
	}

	// Redirect ONLY if the client allowlists the URI. Phishing
	// defense: an attacker who crafts an end_session URL with
	// post_logout_redirect_uri=https://evil.example MUST not get
	// the user bounced there.
	if target != "" {
		ctx.Redirect(http.StatusFound, target)
		return
	}

	// Session killed, but no safe redirect destination. 204 is the
	// OIDC convention for "we did the work, nothing to render".
	ctx.ResponseWriter().WriteHeader(http.StatusNoContent)
}

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
	if err := s.requireDeps(DepClientStore); err != nil {
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
	if err := s.requireDeps(DepClientStore); err != nil {
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

// mfaResumeState is the JSON-encoded blob persisted alongside the
// spi.MFAChallenge. Opaque to spi.MFAChallengeStore backends; the SSO server
// marshals + unmarshals so the post-step-up handler can replay the
// same finishLogin flow the no-MFA path takes.
type mfaResumeState struct {
	Result  *AuthResult  `json:"result"`
	Request loginRequest `json:"request"`
}

// issueMFAChallenge mints a single-use challenge ID + persists the
// frozen login state for resumption. Writes the mfa_required response.
// Audit: emits mfa_required (success outcome — primary credential was
// fine, the user just hasn't completed step-up yet).
func (s *Server) issueMFAChallenge(ctx HandlerContext, result *AuthResult, req loginRequest, client *Client) {
	stateBlob, err := json.Marshal(&mfaResumeState{Result: result, Request: req})
	if err != nil {
		s.logger.Error("mfa: failed to marshal resume state", "error", err, "client", client.ID, "user", result.UserID)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}
	id, err := newMFAChallengeID()
	if err != nil {
		s.logger.Error("mfa: failed to mint challenge id", "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}
	ttl := s.mfaChallengeTTL
	if ttl <= 0 {
		ttl = spi.DefaultMFAChallengeTTL
	}
	now := time.Now()
	challenge := &spi.MFAChallenge{
		ID:           id,
		SubjectID:    result.UserID,
		ClientID:     client.ID,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
		RequestState: stateBlob,
	}
	if err := s.mfaChallengeStore.Put(ctx.Request().Context(), challenge); err != nil {
		s.logger.Error("mfa: failed to persist challenge", "error", err, "client", client.ID, "user", result.UserID)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}

	if s.auditor != nil {
		evt := &audit.Event{
			Type:     audit.EventMFARequired,
			Outcome:  audit.OutcomeSuccess,
			ActorID:  result.UserID,
			ClientID: client.ID,
			Provider: result.Provider,
			ActorIP:  clientIP(ctx.Request()),
		}
		setMeta(evt, KeyMFAChallengeID, id)
		s.auditor.Record(ctx.Request().Context(), evt)
	}

	methods := s.mfaProvider.SupportedMethods()
	// Metric: count one challenge per issuance, labeled by the FIRST
	// supported method (the user picks among them downstream). Zero
	// traffic when metrics aren't wired.
	if s.metrics != nil && len(methods) > 0 {
		s.metrics.MFAChallengesTotal.WithLabelValues(methods[0]).Inc()
	}
	resp := map[string]any{
		KeyError:          ErrMFARequired, // top-level error field so SPAs treating non-2xx-but-pending uniformly still surface it
		KeyMFAChallengeID: id,
		KeyMFAMethods:     methods,
		KeyIss:            s.resolveIssuer(ctx),
	}

	// spi.MFABeginner dispatch: providers needing server-side state
	// (WebAuthn challenge issuance, push notification fan-out, …)
	// get one Begin call per supported method. Results are bucketed
	// per method so clients picking method X read only their slice.
	// Per-method failure is non-fatal — the method stays in
	// mfa_methods but without an attached method_data entry; the
	// client can retry out-of-band or pick a different factor.
	if beginner, ok := s.mfaProvider.(spi.MFABeginner); ok && len(methods) > 0 {
		methodData := make(map[string]map[string]string, len(methods))
		for _, method := range methods {
			data, berr := beginner.Begin(ctx.Request().Context(), result.UserID, method)
			if berr != nil {
				s.logger.Error("mfa: begin failed", "method", method, "user", result.UserID, "error", berr)
				continue
			}
			if len(data) > 0 {
				methodData[method] = data
			}
		}
		if len(methodData) > 0 {
			resp[KeyMFAMethodData] = methodData
		}
	}

	if req.State != "" {
		resp[KeyState] = req.State
	}
	// HTTP 200 (not 400) — the primary credential was accepted; the
	// pending state is a normal step in the flow, not an error.
	ctx.JSON(http.StatusOK, resp)
}

// handleMFAComplete is the POST /auth/mfa endpoint. The client presents
// the challenge ID + factor name + method-specific params; on success
// the server replays finishLogin against the frozen state so the
// response shape matches what the no-MFA path would have returned.
//
// Oracle-leak hardening: every failure path (missing challenge,
// expired, wrong method, wrong factor) collapses to the same
// HTTP 400 + error=mfa_invalid response so probes can't distinguish
// the cases.
func (s *Server) handleMFAComplete(ctx HandlerContext) {
	// Observe /auth/mfa duration with outcome label. defer + named
	// outcome lets every return path (auth-invalid, factor-failed,
	// success, transport-error) account uniformly. The Push factor's
	// long polling loop dominates this histogram — operators
	// alerting on push-flow stalls graph p95 here.
	start := time.Now()
	outcome := "failure"
	defer func() {
		if s.metrics != nil {
			s.metrics.MFACompletionDuration.WithLabelValues(outcome).Observe(time.Since(start).Seconds())
		}
	}()

	tokenNoStoreHeaders(ctx)
	if s.mfaProvider == nil || s.mfaChallengeStore == nil {
		// Endpoint is registered unconditionally so discovery doesn't
		// have to be re-derived per request, but without a wired
		// provider it can't do useful work. 404 (not 501) so a probe
		// can't fingerprint the deployment as MFA-capable-but-misconfigured.
		ctx.JSON(http.StatusNotFound, s.authzErrorBody(ctx, ErrMFAInvalid))
		return
	}
	// Mark outcome on the one success path; left as "failure" for
	// every other return point.
	_ = outcome

	var req struct {
		ChallengeID string            `json:"mfa_challenge_id"`
		Method      string            `json:"mfa_method"`
		Params      map[string]string `json:"params"`
		// Top-level convenience fields the flat-form callers prefer
		// (HTML forms, simple clients). When Params is empty we
		// collect the per-method known fields from these.
		Code      string `json:"code"`      // totp
		Assertion string `json:"assertion"` // webauthn
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return
	}
	if req.ChallengeID == "" || req.Method == "" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return
	}

	challenge, err := s.mfaChallengeStore.Consume(ctx.Request().Context(), req.ChallengeID)
	if err != nil || challenge == nil {
		s.recordMFAFailure(ctx, "", req.ChallengeID, req.Method, "challenge_invalid")
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return
	}

	// Flat → Params normalization. Params wins when both set so explicit
	// callers stay in control. The dispatch into spi.MFAProvider is opaque
	// — only the contract for "totp" / "webauthn" is known here; richer
	// providers (push notification, hardware key) get whatever Params
	// the caller supplies plus the flat code/assertion convenience.
	params := req.Params
	if params == nil {
		params = make(map[string]string, 2)
	}
	if _, ok := params["code"]; !ok && req.Code != "" {
		params["code"] = req.Code
	}
	if _, ok := params["assertion"]; !ok && req.Assertion != "" {
		params["assertion"] = req.Assertion
	}

	if err := s.mfaProvider.Verify(ctx.Request().Context(), challenge.SubjectID, req.Method, params); err != nil {
		s.recordMFAFailure(ctx, challenge.SubjectID, req.ChallengeID, req.Method, err.Error())
		s.recordMFACompletion(req.Method, "failure")
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return
	}
	s.recordMFACompletion(req.Method, "success")
	outcome = "success"

	// Factor verified. Decode the frozen state, re-look-up the client
	// (could have been deactivated / tenant-suspended in the window
	// between challenge issue and verify), and resume finishLogin.
	state := &mfaResumeState{}
	if err := json.Unmarshal(challenge.RequestState, state); err != nil {
		s.logger.Error("mfa: failed to decode resume state", "error", err, "challenge", req.ChallengeID)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}
	if state.Result == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}

	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrClientStoreNotConfigured))
		return
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), challenge.ClientID)
	if err != nil || client == nil || !client.Active || !clientTenantOK(ctx, client) {
		// Client was deactivated, deleted, or tenant-suspended between
		// challenge issue and completion. Surface as inactive_client
		// rather than mfa_invalid — operators investigating the audit
		// trail need to know it wasn't the factor that failed.
		s.recordMFAFailure(ctx, challenge.SubjectID, req.ChallengeID, req.Method, "client_unavailable")
		ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrInactiveClient))
		return
	}

	if s.auditor != nil {
		evt := &audit.Event{
			Type:     audit.EventMFASuccess,
			Outcome:  audit.OutcomeSuccess,
			ActorID:  challenge.SubjectID,
			ClientID: client.ID,
			Provider: state.Result.Provider,
			ActorIP:  clientIP(ctx.Request()),
		}
		setMeta(evt, KeyMFAMethod, req.Method)
		setMeta(evt, KeyMFAChallengeID, req.ChallengeID)
		s.auditor.Record(ctx.Request().Context(), evt)
	}

	// Resume the standard post-risk login flow. finishLogin writes
	// the response, which can be the normal token/code/form-post
	// payload — caller can't tell the difference between an MFA-gated
	// login and a non-gated one (other than the extra round trip).
	s.finishLogin(ctx, state.Result, state.Request, client)
}

// recordMFACompletion increments the MFA completion metric for the
// (method, outcome) pair, but only when the metric is wired AND the
// method appears in the configured provider's SupportedMethods set.
// Restricting to known methods bounds metric cardinality — a
// user-controlled method field would otherwise let attackers spray
// arbitrary labels into Prometheus storage.
func (s *Server) recordMFACompletion(method, outcome string) {
	if s.metrics == nil || s.mfaProvider == nil {
		return
	}
	if slices.Contains(s.mfaProvider.SupportedMethods(), method) {
		s.metrics.MFACompletionsTotal.WithLabelValues(method, outcome).Inc()
	}
}

// recordMFAFailure emits the mfa_failure audit event with the
// operator-visible reason. The wire response is always mfa_invalid;
// reason here is for SIEM investigation, never returned to the client.
func (s *Server) recordMFAFailure(ctx HandlerContext, subjectID, challengeID, method, reason string) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventMFAFailure,
		Outcome: audit.OutcomeFailure,
		ActorID: subjectID,
		ActorIP: clientIP(ctx.Request()),
		Reason:  reason,
	}
	if method != "" {
		setMeta(evt, KeyMFAMethod, method)
	}
	if challengeID != "" {
		setMeta(evt, KeyMFAChallengeID, challengeID)
	}
	s.auditor.Record(ctx.Request().Context(), evt)
}

// newMFAChallengeID mints a 32-byte crypto/rand identifier encoded as
// URL-safe base64 without padding (so it survives query params /
// path segments / form bodies unchanged). 256 bits of entropy — same
// strength as oauth.AuthCodeStore / oauth.DeviceCodeStore identifiers.
func newMFAChallengeID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mfa: rand.Read: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// userCodeAlphabet matches defaultimpl's — base32 minus easily-confused
// glyphs. Duplicated here so handle_device.go doesn't import defaultimpl
// (which would create an import cycle).
const handlerUserCodeAlphabet = "BCDFGHJKMNPQRSTVWXYZ23456789"

// generateDeviceCodeBytes mints a 32-byte base64url device_code.
func generateDeviceCodeBytes() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// generateUserCodeBytes mints an 8-char dashed user_code (XXXX-XXXX)
// from the ambiguous-glyph-free alphabet.
func generateUserCodeBytes() (string, error) {
	const length = 8
	out := make([]byte, length)
	for i := range length {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(handlerUserCodeAlphabet))))
		if err != nil {
			return "", err
		}
		out[i] = handlerUserCodeAlphabet[n.Int64()]
	}
	return string(out[:4]) + "-" + string(out[4:]), nil
}

// handleDeviceCode is the device-initiated endpoint of RFC 8628.
// The device POSTs its client_id (+ optional scope), the server
// returns device_code + user_code + verification_uri + interval +
// expires_in. The device then displays user_code + verification_uri
// to the user and starts polling /token.
func (s *Server) handleDeviceCode(ctx HandlerContext) {
	if s.deviceCodeStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrDeviceCodeNotConfigured))
		return
	}
	if err := s.requireDeps(DepClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	var req struct {
		ClientID string   `json:"client_id"`
		Scope    string   `json:"scope"`
		Nonce    string   `json:"nonce"`
		Resource []string `json:"resource"` // RFC 8707 resource indicators
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if req.ClientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrMissingClientID))
		return
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return
	}
	if !client.Active {
		ctx.JSON(http.StatusForbidden, errorBody(ErrInactiveClient))
		return
	}
	if !clientTenantOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, errorBody(ErrTenantMismatch))
		return
	}
	if !client.AreResourcesAllowed(req.Resource) {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidTarget))
		return
	}

	deviceCode, err := generateDeviceCodeBytes()
	if err != nil {
		s.logger.Error("device code generation failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	userCode, err := generateUserCodeBytes()
	if err != nil {
		s.logger.Error("user code generation failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	// TTL resolution precedence: per-client > server-wide > default.
	// Same shape as Client.RefreshTokenTTL / Client.AccessTokenTTL.
	ttl := client.DeviceCodeTTL
	if ttl <= 0 {
		ttl = s.deviceCodeTTL
	}
	if ttl <= 0 {
		ttl = DefaultDeviceCodeTTL
	}
	interval := client.DeviceCodePollInterval
	if interval <= 0 {
		interval = s.deviceCodeInterval
	}
	if interval <= 0 {
		interval = DefaultDevicePollMin
	}
	scopes := splitScope(req.Scope)

	// Store the normalized (dashless, uppercase) form as the lookup
	// key so /device/verify accepts the user_code with OR without the
	// cosmetic dash. The dashed form goes back to the device for
	// display only.
	dc := &oauth.DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   normalizeUserCode(userCode),
		ClientID:   client.ID,
		Scopes:     scopes,
		Nonce:      req.Nonce,
		Interval:   interval,
		Resources:  append([]string(nil), req.Resource...),
		ExpiresAt:  time.Now().Add(ttl),
	}
	if err := s.deviceCodeStore.Issue(ctx.Request().Context(), dc); err != nil {
		s.logger.Error("device code issue failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	s.recordDeviceCodeIssued(ctx, client.ID)

	base := s.deviceVerifyBaseURL
	if base == "" {
		base = requestBaseURL(ctx.Request()) + PathDeviceVerify
	}
	complete := base
	if strings.Contains(complete, "?") {
		complete += "&user_code=" + userCode
	} else {
		complete += "?user_code=" + userCode
	}

	ctx.JSON(http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          base,
		"verification_uri_complete": complete,
		"expires_in":                int(ttl.Seconds()),
		"interval":                  int(interval.Seconds()),
	})
}

// handleDeviceVerify is the user-facing approval endpoint. The user
// has already authenticated separately (via /auth/login → bearer
// token, or any other path); they present the bearer here along
// with the user_code they read from the device + an approve/deny
// flag. The server validates both and updates the device code's
// state so the next device poll succeeds (or returns access_denied).
func (s *Server) handleDeviceVerify(ctx HandlerContext) {
	if s.deviceCodeStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrDeviceCodeNotConfigured))
		return
	}
	if err := s.requireDeps(DepTokenIssuer); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	bearer := bearerToken(ctx.Request())
	if bearer == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), bearer)
	if err != nil || claims == nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}

	var req struct {
		UserCode string `json:"user_code"`
		Approve  bool   `json:"approve"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	userCode := normalizeUserCode(req.UserCode)
	if userCode == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	// All user_code lookups go through the normalized form so
	// dashed / dashless / mixed-case inputs all resolve to the same
	// entry (typo tolerance on a code the user typed by hand).
	dc, err := s.deviceCodeStore.GetByUserCode(ctx.Request().Context(), userCode)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}

	provider := ""
	if attrProvider, ok := claims.Extra["provider"]; ok {
		provider = attrProvider
	}

	// dc.UserCode is already the normalized form (we store dashless);
	// approval/denial routes back through the same key.
	if req.Approve {
		if err := s.deviceCodeStore.Approve(ctx.Request().Context(),
			dc.UserCode, claims.Subject, provider, claims.Extra); err != nil {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
	} else {
		if err := s.deviceCodeStore.Deny(ctx.Request().Context(), dc.UserCode); err != nil {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
	}
	s.recordDeviceCodeDecision(ctx, claims.Subject, dc.ClientID, req.Approve)

	ctx.JSON(http.StatusOK, map[string]any{KeyStatus: StatusOK})
}

// handleDeviceTokenGrant is the device's poll path on /token. Called
// from the GrantDeviceCode case in handleToken; pulled out so the
// switch stays readable.
//
// Returns one of the RFC 8628 §3.5 sentinels:
//   - authorization_pending: user hasn't acted yet
//   - slow_down: device polled faster than Interval (RFC says +5s)
//   - access_denied: user explicitly denied
//   - expired_token: TTL elapsed
//   - invalid_grant: unknown code / wrong client
//
// or a standard token response on success.
func (s *Server) handleDeviceTokenGrant(ctx HandlerContext, client *Client, deviceCode string) {
	if s.deviceCodeStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrDeviceCodeNotConfigured))
		return
	}
	if deviceCode == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	dc, err := s.deviceCodeStore.GetByDeviceCode(ctx.Request().Context(), deviceCode)
	if err != nil {
		if errors.Is(err, oauth.ErrDeviceCodeNotFound) {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrExpiredToken))
			return
		}
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}
	// Bind: a device_code issued for client A can't be polled by client B.
	if dc.ClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}

	// slow_down: poll arrived within Interval of the previous poll.
	now := time.Now()
	if !dc.LastPoll.IsZero() && now.Sub(dc.LastPoll) < dc.Interval {
		_ = s.deviceCodeStore.UpdateLastPoll(ctx.Request().Context(), deviceCode, now)
		ctx.JSON(http.StatusBadRequest, errorBody(ErrSlowDown))
		return
	}
	_ = s.deviceCodeStore.UpdateLastPoll(ctx.Request().Context(), deviceCode, now)

	if dc.Denied {
		_ = s.deviceCodeStore.Delete(ctx.Request().Context(), deviceCode)
		ctx.JSON(http.StatusBadRequest, errorBody(ErrAccessDenied))
		return
	}
	if !dc.Approved {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrAuthorizationPending))
		return
	}

	// Approved → mint tokens, then delete the device code (single-use).
	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
		return
	}
	issuedSub := s.applyPairwiseSubject(ctx.Request().Context(), client, dc.UserID)
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID: issuedSub, Provider: dc.Provider, Claims: dc.Attributes,
		Resources: dc.Resources,
		ClientID:  client.ID,
		AuthTime:  time.Now(),
		AMR:       []string{dc.Provider},
		TTL:       client.AccessTokenTTL,
	}, dc.Scopes)
	if err != nil {
		s.logger.Error("device token issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	resp := map[string]any{
		KeyAccessToken:   token.AccessToken,
		KeyTokenType:     token.TokenType,
		KeyExpiresIn:     token.ExpiresIn,
		KeyScope:         token.Scope,
		KeyTokenStrategy: strategy,
	}
	if s.refreshTokenStore != nil {
		// Device grant doesn't accept authorization_details today; pass
		// nil so refresh rotations don't fabricate a binding the user
		// never consented to.
		rt, err := s.issueRefreshToken(ctx.Request().Context(),
			dc.UserID, client.ID, dc.Provider, dc.Scopes, dc.Attributes, "", dc.Resources, nil, "", client.RefreshTokenTTL)
		if err != nil {
			s.logger.Error("refresh token issue failed", "error", err)
		} else {
			resp[KeyRefreshToken] = rt
			s.recordRefreshTokenIssued(ctx, client.ID, dc.UserID, false)
		}
	}
	if slices.Contains(dc.Scopes, ScopeOpenID) && s.idTokenIssuer != nil {
		idToken, err := s.idTokenIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
			Subject:  issuedSub,
			Audience: client.ID,
			Nonce:    dc.Nonce,
			AuthTime: time.Now(),
			AMR:      []string{dc.Provider},
			Claims:   dc.Attributes,
		})
		if err != nil {
			s.logger.Error("id token issue failed", "error", err)
		} else {
			resp[KeyIDToken] = idToken
			s.recordIDTokenIssued(ctx, client.ID, dc.UserID)
		}
	}
	s.recordTokenIssued(ctx, client.ID, strategy, dc.UserID)
	s.recordSubjectClientAccess(ctx.Request().Context(), dc.UserID, client.ID)
	_ = s.deviceCodeStore.Delete(ctx.Request().Context(), deviceCode)
	ctx.JSON(http.StatusOK, resp)
}

// normalizeUserCode strips dashes + uppercases for lookup tolerance.
func normalizeUserCode(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, "-", ""))
}

// splitScope parses a space-delimited scope string into a slice,
// returning nil for empty input so the oauth.AuthCode / oauth.DeviceCode entry's
// Scopes field stays nil-not-empty.
func splitScope(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, " ")
}
