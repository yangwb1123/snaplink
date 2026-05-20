package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	neturl "net/url"
	"slices"
	"strings"
	"time"

	"github.com/snaplink/sso/geo"
)

// errorBody returns the standard error envelope { "error": code }.
func errorBody(code string) map[string]string {
	return map[string]string{KeyError: code}
}

// errorBodyWithDescription returns { "error": code, "error_description": desc }.
func errorBodyWithDescription(code, desc string) map[string]string {
	return map[string]string{KeyError: code, KeyErrorDescription: desc}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get(HeaderAuthorization)
	if !strings.HasPrefix(h, BearerPrefix) {
		return ""
	}
	return strings.TrimPrefix(h, BearerPrefix)
}

// clientTenantOK reports whether the given client may be served
// from the request's resolved tenant context. Returns true when:
//   - the client has no TenantID (single-tenant deployment or
//     platform-admin client that belongs to no operator tenant), OR
//   - no tenant resolved on this request (tenant middleware not
//     wired, or unknown host) — pre-multi-tenant deployments
//     never resolved a tenant, and we don't want to suddenly
//     reject every request when the operator first enables a
//     tenant store, OR
//   - the resolved tenant matches the client's TenantID.
//
// Returns false ONLY when both sides are set AND disagree —
// the genuine "client X belongs to tenant Y but is being
// requested under tenant Z" case.
func clientTenantOK(ctx HandlerContext, client *Client) bool {
	if client == nil || client.TenantID == "" {
		return true
	}
	r, ok := TenantFromHandlerContext(ctx)
	if !ok || r == nil || r.Tenant == nil {
		return true
	}
	return r.Tenant.ID == client.TenantID
}

func (s *Server) handleHealth(ctx HandlerContext) {
	ctx.JSON(http.StatusOK, map[string]string{
		KeyStatus: StatusOK,
		KeyIssuer: s.issuer,
	})
}

func (s *Server) handleLogin(ctx HandlerContext) {
	var req struct {
		Provider             string            `json:"provider"`
		Credential           map[string]string `json:"credential"`
		ClientID             string            `json:"client_id"`
		Scope                []string          `json:"scope"`
		State                string            `json:"state"`
		ResponseType         string            `json:"response_type"`         // "code" → return auth code instead of token
		RedirectURI          string            `json:"redirect_uri"`          // required when response_type=code
		Nonce                string            `json:"nonce"`                 // OIDC nonce (passed through to AuthCode)
		CodeChallenge        string            `json:"code_challenge"`        // PKCE RFC 7636 §4.3
		CodeChallengeMethod  string            `json:"code_challenge_method"` // "S256" | "plain" (default plain per §4.3)
		Resource             []string          `json:"resource"`              // RFC 8707 resource indicators
		RequestURI           string            `json:"request_uri"`           // RFC 9126 PAR
		AuthorizationDetails json.RawMessage   `json:"authorization_details"` // RFC 9396
		Request              string            `json:"request"`               // RFC 9101 JAR
		Prompt               string            `json:"prompt"`                // OIDC Core §3.1.2.1: space-separated none|login|consent|select_account
		IDTokenHint          string            `json:"id_token_hint"`         // OIDC Core §3.1.2.1: identifies the subject for prompt=none
		MaxAge               *int64            `json:"max_age"`               // OIDC Core §3.1.2.1: max allowed auth age in seconds (pointer so 0 is distinguishable from absent)
	}
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequest, err.Error()))
		return
	}

	// RFC 9126 §4: when request_uri is present, fetch the pushed
	// authorization parameters and merge them into the in-flight
	// request. The PAR record holds the AUTHORIZATION-SHAPED params
	// (response_type, redirect_uri, scope, etc.) — credentials still
	// arrive on this request, so PAR can't be used to bypass user
	// authentication. The merge gives PAR fields priority over
	// caller-supplied so a tampered redirect parameter can't override
	// what the client previously committed to.
	if req.RequestURI != "" {
		if s.parStore == nil {
			ctx.JSON(http.StatusNotImplemented, s.authzErrorBody(ctx, ErrPARNotConfigured))
			return
		}
		stored, err := s.parStore.Consume(ctx.Request().Context(), req.RequestURI)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
			return
		}
		// Client identity from PAR is authoritative — clients
		// authenticated at /par; an attacker shouldn't be able to
		// flip client_id at the user-agent redirect step.
		if stored.ClientID != "" {
			req.ClientID = stored.ClientID
		}
		if stored.ResponseType != "" {
			req.ResponseType = stored.ResponseType
		}
		if stored.RedirectURI != "" {
			req.RedirectURI = stored.RedirectURI
		}
		if len(stored.Scope) > 0 {
			req.Scope = stored.Scope
		}
		if stored.State != "" {
			req.State = stored.State
		}
		if stored.Nonce != "" {
			req.Nonce = stored.Nonce
		}
		if stored.CodeChallenge != "" {
			req.CodeChallenge = stored.CodeChallenge
			req.CodeChallengeMethod = stored.CodeChallengeMethod
		}
		if len(stored.Resource) > 0 {
			req.Resource = stored.Resource
		}
		if len(stored.AuthorizationDetails) > 0 {
			// RFC 9396 + RFC 9126: PAR's value is committing the
			// authorization request authoritatively up-front, so the
			// pushed authorization_details wins over any caller-
			// supplied value at /auth/login (mirrors how PAR's
			// scope/resource/redirect_uri override the redirect-time
			// parameters).
			req.AuthorizationDetails = cloneRawJSON(stored.AuthorizationDetails)
		}
	}

	// OIDC Core §3.1.2.1 prompt parameter — parse early so the
	// silent-renewal branch can override the providers-list probe
	// and the credential-validation pipeline alike. prompt=none
	// stays in the iframe contract (no UI, no credentials): the
	// only valid response is either a renewed token (if a session
	// is live) or login_required (§3.1.2.6).
	prompts := parsePromptValues(req.Prompt)
	if promptHasNone(prompts) {
		// Silent renewal needs the client resolved to verify
		// id_token_hint binding. Mirror the validation guards the
		// post-probe path runs so a misconfigured caller still
		// gets a coherent error.
		if req.ClientID == "" {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMissingClientID))
			return
		}
		if s.clientStore == nil {
			ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrClientStoreNotConfigured))
			return
		}
		c, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, s.authzErrorBody(ctx, ErrInvalidClient))
			return
		}
		if !c.Active {
			ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrInactiveClient))
			return
		}
		if !clientTenantOK(ctx, c) {
			ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrTenantMismatch))
			return
		}
		if s.handleSilentRenewal(ctx, prompts, silentRenewalRequest{
			ClientID:             req.ClientID,
			Scope:                req.Scope,
			State:                req.State,
			Nonce:                req.Nonce,
			Resource:             req.Resource,
			AuthorizationDetails: req.AuthorizationDetails,
			IDTokenHint:          req.IDTokenHint,
			MaxAge:               req.MaxAge,
		}, c) {
			return
		}
	}

	if req.Provider == "" {
		ctx.JSON(http.StatusOK, map[string]any{
			KeyProviders: s.providersForClient(ctx, req.ClientID),
			KeyIss:       s.resolveIssuer(ctx),
		})
		return
	}

	if req.ClientID == "" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMissingClientID))
		return
	}
	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrClientStoreNotConfigured))
		return
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidClient)
		ctx.JSON(http.StatusUnauthorized, s.authzErrorBody(ctx, ErrInvalidClient))
		return
	}
	if !client.Active {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInactiveClient)
		ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrInactiveClient))
		return
	}
	if !clientTenantOK(ctx, client) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrTenantMismatch)
		ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrTenantMismatch))
		return
	}
	if !client.IsAuthenticatorAllowed(req.Provider) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrAuthenticatorNotAllowed)
		ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrAuthenticatorNotAllowed))
		return
	}

	// RFC 9101 JAR: when the `request` parameter is present, the
	// authorization request parameters live inside a signed JWT.
	// Verify it against the client's registered JWKS, then merge
	// JWT claims into req with JWT taking precedence on conflict
	// (matches PAR's merge semantics; FAPI 2.0's "ignore all
	// outside" mode is reserved for a future strict flag).
	if req.Request != "" {
		jar, jarErr := verifyJAR(ctx.Request().Context(), req.Request, client, s.resolveIssuer(ctx), s.jtiReplayStore)
		if jarErr != nil {
			s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequestObject)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequestObject, jarErr.Error()))
			return
		}
		if jar.ResponseType != "" {
			req.ResponseType = jar.ResponseType
		}
		if jar.RedirectURI != "" {
			req.RedirectURI = jar.RedirectURI
		}
		if jar.Scope != "" {
			req.Scope = strings.Split(jar.Scope, " ")
		}
		if jar.State != "" {
			req.State = jar.State
		}
		if jar.Nonce != "" {
			req.Nonce = jar.Nonce
		}
		if jar.CodeChallenge != "" {
			req.CodeChallenge = jar.CodeChallenge
			req.CodeChallengeMethod = jar.CodeChallengeMethod
		}
		if len(jar.Resource) > 0 {
			req.Resource = jar.Resource
		}
		if len(jar.AuthorizationDetails) > 0 {
			req.AuthorizationDetails = cloneRawJSON(jar.AuthorizationDetails)
		}
	}

	// RFC 8707 §2: each requested `resource` MUST be allowlisted on
	// the client. Empty allowlist disables enforcement (legacy compat).
	if !client.AreResourcesAllowed(req.Resource) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidTarget)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidTarget))
		return
	}
	// RFC 9396 §6: authorization_details, when present, MUST be a
	// JSON array of {type, ...} objects, and (if the client
	// declared an allowlist) every element's type MUST match.
	// Empty allowlist = parameter accepted but unconstrained
	// (legacy compat).
	if _, err := validateAuthorizationDetails(req.AuthorizationDetails, client.AllowedAuthorizationDetailsTypes); err != nil {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidAuthorizationDetails)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidAuthorizationDetails, err.Error()))
		return
	}

	auth, err := s.getAuthenticator(req.Provider)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrUnsupportedProvider))
		return
	}

	loginURL := auth.LoginURL(req.State)
	if loginURL != "" {
		ctx.Redirect(http.StatusFound, loginURL)
		return
	}

	// Per-account lockout gate: BEFORE invoking the credential
	// verifier, check whether the (client, identifier) pair is
	// currently locked. Skips the verifier entirely on a locked
	// account so a botnet can't drain the verifier's
	// constant-time hash budget while the lock is active.
	lockKey := lockoutKey(req.ClientID, req.Credential)
	if s.accountLockout != nil && lockKey != "" {
		if locked, until, _ := s.accountLockout.IsLocked(ctx.Request().Context(), lockKey); locked {
			s.recordAccountLocked(ctx, req.ClientID, req.Provider, lockKey, until)
			ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrAccountLocked))
			return
		}
	}

	result, err := auth.Authenticate(ctx.Request().Context(), &AuthRequest{
		Provider:   req.Provider,
		Credential: req.Credential,
		ClientID:   req.ClientID,
		Scope:      req.Scope,
		State:      req.State,
	})
	if err != nil {
		s.logger.Error("authentication failed", "provider", req.Provider, "error", err)
		// Failure attribution to per-account lockout BEFORE the
		// generic login_failure audit so the auditor records the
		// lockout state alongside the failure.
		if s.accountLockout != nil && lockKey != "" {
			if locked, until, _ := s.accountLockout.RegisterFailure(ctx.Request().Context(), lockKey); locked {
				s.recordAccountLocked(ctx, req.ClientID, req.Provider, lockKey, until)
				ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrAccountLocked))
				return
			}
		}
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidCredentials)
		ctx.JSON(http.StatusUnauthorized, s.authzErrorBody(ctx, ErrInvalidCredentials))
		return
	}

	// Successful credential validation clears any pending failure
	// counter for this (client, identifier) — a single legit
	// login resets the brute-force budget. Done BEFORE risk
	// evaluation so a risk-denied login doesn't unlock the
	// account (risk decisions might want the lock to stay
	// engaged for repeat-offender patterns).
	if s.accountLockout != nil && lockKey != "" {
		_ = s.accountLockout.RegisterSuccess(ctx.Request().Context(), lockKey)
	}

	// Risk evaluation. Skipped entirely (zero overhead) when no scorer
	// configured. Scorer errors fail OPEN by contract — failing closed
	// on a misbehaving scorer locks every user out. Operators worried
	// about silent bypass should alert on "risk scorer failed".
	if s.riskScorer != nil {
		var geoInfo *geo.GeoInfo
		if g, ok := GeoFromHandlerContext(ctx); ok {
			geoInfo = g
		}
		assessment, riskErr := s.riskScorer.Score(ctx.Request().Context(), &RiskRequest{
			SubjectID: result.UserID,
			ClientID:  req.ClientID,
			Provider:  req.Provider,
			RemoteIP:  clientIP(ctx.Request()),
			UserAgent: ctx.Request().UserAgent(),
			Geo:       geoInfo,
			Timestamp: time.Now(),
		})
		switch {
		case riskErr != nil:
			s.logger.Error("risk scorer failed", "error", riskErr, "user", result.UserID, "client", req.ClientID)
		case assessment == nil:
			// Defensive: a scorer that returns (nil, nil) is misbehaving.
			s.logger.Error("risk scorer returned nil assessment", "user", result.UserID, "client", req.ClientID)
		default:
			if s.metrics != nil {
				s.metrics.RiskDecisionsTotal.WithLabelValues(string(assessment.Decision)).Inc()
			}
			if assessment.Decision == DecisionDeny {
				s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrRiskDenied)
				ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrRiskDenied))
				return
			}
			// DecisionRequireMFA: documented in risk.go as future-reserved.
			// Today we treat it as Allow (so a forward-looking scorer can
			// emit it without breaking flows). When MFA orchestration lands,
			// this branch returns a challenge response.
		}
	}

	if s.userProvider != nil {
		user := &User{
			ID:         result.UserID,
			ExternalID: result.ExternalID,
			Provider:   result.Provider,
			Attributes: result.Attributes,
		}
		if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), user); err != nil {
			s.logger.Error("failed to upsert user", "error", err)
			ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
			return
		}
	}

	// OAuth 2.1 strict mode: response_type=token (implicit) is
	// retired by OAuth 2.1; empty response_type (which defaulted
	// to direct-mint in OAuth 2.0) is treated the same way under
	// strict mode. Both reject with unsupported_response_type
	// — strict mode requires explicit response_type=code.
	if s.oauth21Strict && req.ResponseType != "code" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrUnsupportedResponseType))
		return
	}

	// OAuth 2.0 authorization_code branch: instead of minting a token
	// here, persist a short-lived code bound to (user, client, redirect_uri)
	// and return it so the relying party can exchange it via /token.
	if req.ResponseType == "code" {
		if s.authCodeStore == nil {
			ctx.JSON(http.StatusNotImplemented, s.authzErrorBody(ctx, ErrAuthCodeNotConfigured))
			return
		}
		if req.RedirectURI == "" || !client.IsRedirectURIValid(req.RedirectURI) {
			s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRedirectURI)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRedirectURI))
			return
		}
		// OAuth 2.1 §4.1.3 — redirect_uri MUST use https. Localhost
		// (any port) remains permitted for development workflows.
		if s.oauth21Strict && !isSecureRedirectURI(req.RedirectURI) {
			s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRedirectURI)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRedirectURI))
			return
		}
		// PKCE validation per RFC 7636 §4.3:
		// * If client policy requires PKCE, code_challenge MUST be set.
		// * OAuth 2.1 §4.1.1 makes PKCE mandatory; strict mode honors
		//   that even when the client has RequirePKCE=false set.
		// * If code_challenge IS set, length and method MUST be valid.
		// * Empty method defaults to "plain" per §4.3 (callers should
		//   prefer S256; "plain" stays for legacy interop).
		if req.CodeChallenge == "" {
			if client.RequirePKCE || s.oauth21Strict {
				s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrPKCERequired)
				ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrPKCERequired))
				return
			}
		} else {
			if l := len(req.CodeChallenge); l < PKCEVerifierMinLen || l > PKCEVerifierMaxLen {
				s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequest)
				ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequest))
				return
			}
			if !isValidPKCEMethod(req.CodeChallengeMethod) {
				s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidPKCEMethod)
				ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidPKCEMethod))
				return
			}
			if req.CodeChallengeMethod == "" {
				req.CodeChallengeMethod = PKCEMethodPlain
			}
		}
		code, err := s.issueAuthCode(ctx.Request().Context(), result, &req, client)
		if err != nil {
			s.logger.Error("failed to issue auth code", "error", err)
			ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
			return
		}
		s.recordLoginSuccess(ctx, client.ID, req.Provider, "code", result.UserID, "")
		resp := map[string]any{
			KeyCode: code,
			KeyIss:  s.resolveIssuer(ctx),
		}
		if req.State != "" {
			resp[KeyState] = req.State
		}
		ctx.JSON(http.StatusOK, resp)
		return
	}
	if req.ResponseType != "" && req.ResponseType != "token" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrUnsupportedResponseType))
		return
	}

	if s.sessionMgr == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrSessionMgrNotConfigured))
		return
	}
	session, err := s.sessionMgr.Create(ctx.Request().Context(), result.UserID)
	if err != nil {
		s.logger.Error("failed to create session", "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}

	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		s.logger.Error("no token strategy for client", "client", client.ID, "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrNoTokenStrategy))
		return
	}
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID:                   result.UserID,
		Provider:             result.Provider,
		Claims:               result.Attributes,
		Resources:            append([]string(nil), req.Resource...),
		ClientID:             client.ID,
		AuthTime:             time.Now(),
		AMR:                  []string{result.Provider},
		AuthorizationDetails: cloneRawJSON(req.AuthorizationDetails),
		SID:                  session.ID,
	}, req.Scope)
	if err != nil {
		s.logger.Error("failed to issue token", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}

	s.recordLoginSuccess(ctx, client.ID, req.Provider, strategy, result.UserID, session.ID)
	s.recordSubjectClientAccess(ctx.Request().Context(), result.UserID, client.ID)

	// Geo enrichment: if the authenticator didn't supply
	// country/language hints, fall back to whatever the geo
	// middleware stashed on the request. Authenticators with a
	// stronger signal (SIM region, account default, explicit user
	// pref) override the geo guess by setting them themselves.
	// One Get to avoid two ctx.Get round trips.
	if result.CountryCode == "" || result.RecommendedLanguage == "" {
		if info, ok := GeoFromHandlerContext(ctx); ok {
			if result.CountryCode == "" {
				result.CountryCode = info.CountryCode
			}
			if result.RecommendedLanguage == "" {
				result.RecommendedLanguage = info.RecommendedLanguage
			}
		}
	}

	// When a RefreshTokenStore is wired, server-managed refresh tokens
	// override whatever the underlying TokenIssuer returned — that way
	// the OAuth refresh_token grant works uniformly regardless of which
	// issuer minted the access token. Fail-open: a refresh-token store
	// outage doesn't block the login (user gets an access_token they
	// can use until expiry), but it does surface as a server-side
	// logger.Error so operators see the degradation.
	refreshTokenOut := token.RefreshToken
	if s.refreshTokenStore != nil {
		rt, err := s.issueRefreshToken(ctx.Request().Context(),
			result.UserID, client.ID, result.Provider, req.Scope, result.Attributes, "", req.Resource,
			req.AuthorizationDetails, session.ID)
		if err != nil {
			s.logger.Error("refresh token issue failed", "error", err, "client", client.ID, "user", result.UserID)
		} else {
			refreshTokenOut = rt
			s.recordRefreshTokenIssued(ctx, client.ID, result.UserID, false)
		}
	}

	resp := map[string]any{
		KeySessionID:     session.ID,
		KeyAccessToken:   token.AccessToken,
		KeyTokenType:     token.TokenType,
		KeyRefreshToken:  refreshTokenOut,
		KeyExpiresIn:     token.ExpiresIn,
		KeyScope:         token.Scope,
		KeyTokenStrategy: strategy,
		KeyIss:           s.resolveIssuer(ctx),
	}
	// OIDC ID Token: emit alongside the access token whenever the
	// caller requested "openid" scope AND an issuer is wired. Errors
	// fail open — a misconfigured ID-token issuer shouldn't block the
	// underlying authentication, the relying party just won't get
	// id_token in the response.
	if hasOpenIDScope(req.Scope) && s.idTokenIssuer != nil {
		idToken, err := s.idTokenIssuer.IssueIDToken(ctx.Request().Context(), &IDTokenRequest{
			Subject:  result.UserID,
			Audience: client.ID,
			Nonce:    req.Nonce,
			AuthTime: time.Now(),
			AMR:      []string{result.Provider},
			Claims:   result.Attributes,
			SID:      session.ID,
		})
		if err != nil {
			s.logger.Error("id token issue failed", "error", err, "client", client.ID, "user", result.UserID)
		} else {
			resp[KeyIDToken] = idToken
			s.recordIDTokenIssued(ctx, client.ID, result.UserID)
		}
	}
	if result.CountryCode != "" {
		resp[KeyCountryCode] = result.CountryCode
	}
	if result.RecommendedLanguage != "" {
		resp[KeyRecommendedLang] = result.RecommendedLanguage
	}
	if s.embedPermissions {
		roles, perms, menus := s.resolvePermissionsForLogin(ctx.Request().Context(), result.UserID, client.ID)
		resp[KeyRoles] = roles
		resp[KeyPermissions] = perms
		resp[KeyMenus] = menus
	}
	ctx.JSON(http.StatusOK, resp)
}

// issueAuthCode generates an authorization code, persists it against the
// store, and returns the opaque code string. The TTL is taken from the
// Server's authCodeTTL with a fallback to DefaultAuthCodeTTL.
func (s *Server) issueAuthCode(
	ctx context.Context,
	result *AuthResult,
	req *struct {
		Provider             string            `json:"provider"`
		Credential           map[string]string `json:"credential"`
		ClientID             string            `json:"client_id"`
		Scope                []string          `json:"scope"`
		State                string            `json:"state"`
		ResponseType         string            `json:"response_type"`
		RedirectURI          string            `json:"redirect_uri"`
		Nonce                string            `json:"nonce"`
		CodeChallenge        string            `json:"code_challenge"`
		CodeChallengeMethod  string            `json:"code_challenge_method"`
		Resource             []string          `json:"resource"`
		RequestURI           string            `json:"request_uri"`
		AuthorizationDetails json.RawMessage   `json:"authorization_details"`
		Request              string            `json:"request"`
		Prompt               string            `json:"prompt"`
		IDTokenHint          string            `json:"id_token_hint"`
		MaxAge               *int64            `json:"max_age"`
	},
	client *Client,
) (string, error) {
	code, err := generateAuthCodeBytes()
	if err != nil {
		return "", fmt.Errorf("generate auth code: %w", err)
	}
	ttl := s.authCodeTTL
	if ttl <= 0 {
		ttl = DefaultAuthCodeTTL
	}
	entry := &AuthCode{
		UserID:               result.UserID,
		ClientID:             client.ID,
		RedirectURI:          req.RedirectURI,
		Scopes:               append([]string(nil), req.Scope...),
		Nonce:                req.Nonce,
		Provider:             result.Provider,
		Attributes:           result.Attributes,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		Resources:            append([]string(nil), req.Resource...),
		AuthorizationDetails: cloneRawJSON(req.AuthorizationDetails),
		ExpiresAt:            time.Now().Add(ttl),
	}
	if err := s.authCodeStore.Issue(ctx, code, entry); err != nil {
		return "", fmt.Errorf("store auth code: %w", err)
	}
	return code, nil
}

// isSecureRedirectURI reports whether the URI satisfies the OAuth 2.1
// §4.1.3 redirect_uri security profile: scheme=https required for
// public hosts; http://localhost (or http://127.0.0.1 / [::1]) on any
// port stays permitted so development workflows don't need a local
// TLS terminator. URIs that fail to parse return false (closed
// default), which collapses to invalid_redirect_uri on the caller.
func isSecureRedirectURI(uri string) bool {
	u, err := neturl.Parse(uri)
	if err != nil || u == nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return false
}

// isValidPKCEMethod reports whether the named PKCE challenge method is
// one we support. Empty defaults to "plain" per RFC 7636 §4.3 (the
// caller stamps the default after this check); "S256" is the strongly
// recommended method for production.
func isValidPKCEMethod(method string) bool {
	return method == "" || method == PKCEMethodPlain || method == PKCEMethodS256
}

// verifyPKCE returns true when the supplied verifier derives to the
// stored challenge under the named method. Constant-time comparison
// closes off timing-oracle attacks on the challenge value.
//
// An empty challenge means no PKCE binding was set at issue; callers
// MUST NOT invoke this helper in that case (the exchange skips PKCE
// entirely when info.CodeChallenge is empty — backwards compatible
// with confidential clients).
func verifyPKCE(method, challenge, verifier string) bool {
	switch method {
	case PKCEMethodS256:
		sum := sha256.Sum256([]byte(verifier))
		derived := base64.RawURLEncoding.EncodeToString(sum[:])
		return subtle.ConstantTimeCompare([]byte(derived), []byte(challenge)) == 1
	case PKCEMethodPlain, "":
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 1
	default:
		return false
	}
}

// generateAuthCodeBytes mints a cryptographically random base64url code.
// Local copy so handler.go doesn't depend on defaultimpl.
func generateAuthCodeBytes() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// issueRefreshToken generates a refresh token, persists it against the
// store, and returns the opaque token string. The TTL is taken from the
// Server's refreshTokenTTL with a fallback to DefaultRefreshTokenTTL.
//
// familyID controls the OAuth Security BCP §4.13 family-tracking
// chain: pass "" on the FIRST issue (login, authz_code, device) to
// mint a new family, or the existing FamilyID on rotation to keep
// every descendant of a single authorization event in one family.
// Stores that don't implement RefreshTokenFamilyTracker simply
// ignore the value — opt-in hardening.
//
// Callers MUST pre-check s.refreshTokenStore != nil — this helper
// dereferences it unconditionally so a misuse fails loudly during
// testing rather than silently no-op'ing in production.
func (s *Server) issueRefreshToken(
	ctx context.Context,
	userID, clientID, provider string,
	scopes []string,
	attributes map[string]string,
	familyID string,
	resources []string,
	authDetails json.RawMessage,
	sid string,
) (string, error) {
	token, err := generateAuthCodeBytes() // same 32-byte base64url generator
	if err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	ttl := s.refreshTokenTTL
	if ttl <= 0 {
		ttl = DefaultRefreshTokenTTL
	}
	if familyID == "" {
		// First-issue path: mint a new family. Length matches the
		// token itself — 32 bytes / 256 bits — so collisions across
		// the fleet remain infeasible.
		fid, err := generateAuthCodeBytes()
		if err != nil {
			return "", fmt.Errorf("generate refresh family id: %w", err)
		}
		familyID = fid
	}
	now := time.Now()
	entry := &RefreshToken{
		UserID:               userID,
		ClientID:             clientID,
		Provider:             provider,
		Scopes:               append([]string(nil), scopes...),
		Attributes:           attributes,
		IssuedAt:             now,
		ExpiresAt:            now.Add(ttl),
		FamilyID:             familyID,
		Resources:            append([]string(nil), resources...),
		AuthorizationDetails: cloneRawJSON(authDetails),
		SID:                  sid,
	}
	if err := s.refreshTokenStore.Issue(ctx, token, entry); err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}
	return token, nil
}

// isScopeSubset reports whether every scope in want is also in have.
// Used by the refresh_token grant to enforce RFC 6749 §6's "MUST NOT
// expand scope" rule — a refresh request may downscope or keep the
// original grant but never widen it.
func isScopeSubset(want, have []string) bool {
	if len(want) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; !ok {
			return false
		}
	}
	return true
}

// providersForClient returns the list of authenticator names this client may
// use. Used by GET /auth/login (provider discovery). If clientID is empty or
// not found, all registered providers are returned (backwards compatible).
func (s *Server) providersForClient(ctx HandlerContext, clientID string) []string {
	all := make([]string, 0, len(s.authenticators))
	for name := range s.authenticators {
		all = append(all, name)
	}
	if clientID == "" || s.clientStore == nil {
		return all
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil {
		return all
	}
	if len(client.AllowedAuthenticators) == 0 {
		return all
	}
	out := make([]string, 0, len(all))
	for _, name := range all {
		if client.IsAuthenticatorAllowed(name) {
			out = append(out, name)
		}
	}
	return out
}

func (s *Server) handleCallback(ctx HandlerContext) {
	code := ctx.Query("code")
	state := ctx.Query("state")
	provider := ctx.Query("provider")

	if code == "" || state == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidCallback))
		return
	}

	var auth Authenticator
	var err error
	if provider != "" {
		auth, err = s.getAuthenticator(provider)
	} else {
		for _, a := range s.authenticators {
			if _, err = a.Callback(context.Background(), &CallbackState{Code: code, State: state}); err == nil {
				auth = a
				break
			}
		}
	}

	if auth == nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrUnknownProvider))
		return
	}

	result, err := auth.Callback(context.Background(), &CallbackState{Code: code, State: state})
	if err != nil {
		s.logger.Error("callback failed", "provider", auth.Name(), "error", err)
		s.recordCallbackFailure(ctx, auth.Name(), ErrCallbackFailed)
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrCallbackFailed))
		return
	}

	user := &User{
		ID:         result.UserID,
		ExternalID: result.ExternalID,
		Provider:   result.Provider,
		Attributes: result.Attributes,
	}
	if s.userProvider != nil {
		s.userProvider.CreateOrUpdate(ctx.Request().Context(), user)
	}

	session, err := s.sessionMgr.Create(ctx.Request().Context(), result.UserID)
	if err != nil {
		s.logger.Error("failed to create session", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	ctx.JSON(http.StatusOK, map[string]string{
		KeySessionID: session.ID,
		KeyStatus:    StatusAuthenticated,
	})
}

func (s *Server) handleToken(ctx HandlerContext) {
	if err := s.requireDeps(depTokenIssuer, depClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	var req struct {
		GrantType    string   `json:"grant_type"`
		Code         string   `json:"code"`
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RefreshToken string   `json:"refresh_token"`
		Scope        string   `json:"scope"`
		RedirectURI  string   `json:"redirect_uri"`
		CodeVerifier string   `json:"code_verifier"` // PKCE RFC 7636 §4.5
		DeviceCode   string   `json:"device_code"`   // RFC 8628 §3.4 device grant
		Resource     []string `json:"resource"`      // RFC 8707 resource indicators

		// RFC 8693 token-exchange parameters.
		SubjectToken       string   `json:"subject_token"`
		SubjectTokenType   string   `json:"subject_token_type"`
		ActorToken         string   `json:"actor_token"`
		ActorTokenType     string   `json:"actor_token_type"`
		Audience           []string `json:"audience"`
		RequestedTokenType string   `json:"requested_token_type"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	// HTTP Basic auth takes precedence over body fields per RFC 6749 §2.3.1.
	if id, secret, ok := basicClientCreds(ctx.Request()); ok {
		req.ClientID = id
		req.ClientSecret = secret
	}

	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return
	}
	if !clientTenantOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, errorBody(ErrTenantMismatch))
		return
	}
	if err := s.clientStore.ValidateSecret(ctx.Request().Context(), req.ClientID, req.ClientSecret); err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClientSecret))
		return
	}
	// RFC 8707 §2: each requested `resource` MUST be allowlisted on
	// the client. Empty allowlist disables enforcement (legacy compat).
	if !client.AreResourcesAllowed(req.Resource) {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidTarget))
		return
	}

	var scopes []string
	if req.Scope != "" {
		scopes = strings.Split(req.Scope, " ")
	}

	switch req.GrantType {
	case GrantAuthorizationCode:
		if s.authCodeStore == nil {
			ctx.JSON(http.StatusNotImplemented, errorBody(ErrAuthCodeNotConfigured))
			return
		}
		if req.Code == "" {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
			return
		}
		info, err := s.authCodeStore.Consume(ctx.Request().Context(), req.Code)
		if err != nil {
			// Unknown / expired / already-consumed all map to invalid_grant
			// per RFC 6749 §5.2 — clients can't distinguish, by design.
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
		// Bind the code to the client that's exchanging it.
		if info.ClientID != client.ID {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
		// Bind to the redirect_uri that was registered at issue time.
		if info.RedirectURI != "" && req.RedirectURI != info.RedirectURI {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRedirectURI))
			return
		}
		// PKCE verification per RFC 7636 §4.6: if a challenge was
		// captured at issue, the exchange MUST present a verifier
		// that derives to it under the original method. All failure
		// cases (missing verifier, malformed verifier, wrong verifier)
		// map to invalid_grant — RFC-mandated, and the oracle-leak
		// hardening matches the rest of the code exchange.
		if info.CodeChallenge != "" {
			if l := len(req.CodeVerifier); l < PKCEVerifierMinLen || l > PKCEVerifierMaxLen {
				ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
				return
			}
			if !verifyPKCE(info.CodeChallengeMethod, info.CodeChallenge, req.CodeVerifier) {
				ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
				return
			}
		}
		strategy, ti, err := s.issuerForClient(client)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
			return
		}
		// Prefer the scopes captured at issue time; fall back to whatever
		// the caller supplied so older clients that don't echo the scope
		// param still get a sensible token.
		scopes := info.Scopes
		if len(scopes) == 0 {
			scopes = strings.Split(req.Scope, " ")
		}
		// Resources captured at authorization win over anything the
		// exchange caller supplies (RFC 8707 binds the audience at
		// authorization time, not at token redemption).
		resources := info.Resources
		if len(resources) == 0 {
			resources = req.Resource
		}
		token, err := ti.Issue(ctx.Request().Context(), &Subject{
			ID: info.UserID, Provider: info.Provider, Claims: info.Attributes,
			Resources:            resources,
			ClientID:             client.ID,
			AuthTime:             time.Now(),
			AMR:                  []string{info.Provider},
			AuthorizationDetails: cloneRawJSON(info.AuthorizationDetails),
			SID:                  info.SID,
		}, scopes)
		if err != nil {
			s.logger.Error("token issuance failed", "strategy", strategy, "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
		s.recordTokenIssued(ctx, client.ID, strategy, info.UserID)
		s.recordSubjectClientAccess(ctx.Request().Context(), info.UserID, client.ID)
		resp := map[string]any{
			KeyAccessToken:   token.AccessToken,
			KeyTokenType:     token.TokenType,
			KeyExpiresIn:     token.ExpiresIn,
			KeyScope:         token.Scope,
			KeyTokenStrategy: strategy,
		}
		if s.refreshTokenStore != nil {
			rt, err := s.issueRefreshToken(ctx.Request().Context(),
				info.UserID, client.ID, info.Provider, scopes, info.Attributes, "", info.Resources,
				info.AuthorizationDetails, info.SID)
			if err != nil {
				s.logger.Error("refresh token issue failed", "error", err, "client", client.ID, "user", info.UserID)
			} else {
				resp[KeyRefreshToken] = rt
				s.recordRefreshTokenIssued(ctx, client.ID, info.UserID, false)
			}
		}
		// OIDC ID Token on the authorization_code path: same gate as
		// the direct-mint login flow, but the scope + nonce come from
		// what we captured at issue time, not from the exchange body.
		if hasOpenIDScope(info.Scopes) && s.idTokenIssuer != nil {
			idToken, err := s.idTokenIssuer.IssueIDToken(ctx.Request().Context(), &IDTokenRequest{
				Subject:  info.UserID,
				Audience: client.ID,
				Nonce:    info.Nonce,
				AuthTime: time.Now(),
				AMR:      []string{info.Provider},
				Claims:   info.Attributes,
			})
			if err != nil {
				s.logger.Error("id token issue failed", "error", err, "client", client.ID, "user", info.UserID)
			} else {
				resp[KeyIDToken] = idToken
				s.recordIDTokenIssued(ctx, client.ID, info.UserID)
			}
		}
		ctx.JSON(http.StatusOK, resp)
	case GrantRefreshToken:
		if s.refreshTokenStore == nil {
			ctx.JSON(http.StatusNotImplemented, errorBody(ErrRefreshTokenNotConfigured))
			return
		}
		if req.RefreshToken == "" {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
			return
		}
		info, err := s.refreshTokenStore.Consume(ctx.Request().Context(), req.RefreshToken)
		if err != nil {
			// OAuth Security BCP §4.13: a previously-consumed token
			// presented again is a reuse signal. Kill the whole family
			// (every sibling and descendant) before returning the wire
			// error — an attacker who already rotated after stealing
			// the leaf loses access to the active descendant too.
			if errors.Is(err, ErrRefreshTokenReused) && info != nil && info.FamilyID != "" {
				killed := 0
				if tracker, ok := s.refreshTokenStore.(RefreshTokenFamilyTracker); ok {
					n, derr := tracker.DeleteFamily(ctx.Request().Context(), info.FamilyID)
					if derr != nil {
						s.logger.Error("family revocation on reuse failed",
							"error", derr, "family", info.FamilyID)
					} else {
						killed = n
						s.logger.Error("refresh token reuse detected — family revoked",
							"family", info.FamilyID, "killed", killed,
							"client", client.ID)
					}
				}
				s.recordRefreshTokenReuse(ctx, client.ID, info.FamilyID, killed)
			}
			// Unknown / expired / already-consumed all map to invalid_grant
			// per RFC 6749 §5.2 — clients can't distinguish, by design.
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
		// Bind the token to the client that's exchanging it (RFC 6749 §6).
		if info.ClientID != client.ID {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
		// Scope rules per RFC 6749 §6: omitted scope = keep original;
		// supplied scope MUST be a subset of the original (narrowing
		// allowed, expansion forbidden).
		grantScopes := info.Scopes
		if req.Scope != "" {
			requested := strings.Split(req.Scope, " ")
			if !isScopeSubset(requested, info.Scopes) {
				ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidScope))
				return
			}
			grantScopes = requested
		}
		strategy, ti, err := s.issuerForClient(client)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
			return
		}
		token, err := ti.Issue(ctx.Request().Context(), &Subject{
			ID: info.UserID, Provider: info.Provider, Claims: info.Attributes,
			Resources: info.Resources,
			ClientID:  client.ID,
			// Refresh rotations don't reset auth_time per RFC 9068
			// — the underlying authentication event is the original
			// login, not the refresh exchange. AMR likewise stays
			// the original method.
			AMR: []string{info.Provider},
			// RFC 9396: the authorization_details grant captured
			// at the original authorization survives the rotation
			// — refreshed tokens MUST carry the same fine-grained
			// authorization the user already consented to.
			AuthorizationDetails: cloneRawJSON(info.AuthorizationDetails),
			// SID is locked to the original authorization's
			// session — rotation never opens a new session.
			SID: info.SID,
		}, grantScopes)
		if err != nil {
			s.logger.Error("token issuance failed", "strategy", strategy, "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
		// Rotation: issue a NEW refresh token (the old one was deleted by
		// Consume above). Pass info.FamilyID so the new leaf joins the
		// same family — stores that track families can detect any
		// future reuse anywhere in the chain. A presented-twice old
		// token now fails as invalid_grant (and kills the family).
		newRefresh, err := s.issueRefreshToken(ctx.Request().Context(),
			info.UserID, client.ID, info.Provider, grantScopes, info.Attributes, info.FamilyID, info.Resources,
			info.AuthorizationDetails, info.SID)
		if err != nil {
			s.logger.Error("refresh token rotation failed", "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
		s.recordTokenIssued(ctx, client.ID, strategy, info.UserID)
		s.recordRefreshTokenIssued(ctx, client.ID, info.UserID, true)
		s.recordSubjectClientAccess(ctx.Request().Context(), info.UserID, client.ID)
		ctx.JSON(http.StatusOK, map[string]any{
			KeyAccessToken:   token.AccessToken,
			KeyTokenType:     token.TokenType,
			KeyRefreshToken:  newRefresh,
			KeyExpiresIn:     token.ExpiresIn,
			KeyScope:         token.Scope,
			KeyTokenStrategy: strategy,
		})
	case GrantDeviceCode:
		s.handleDeviceTokenGrant(ctx, client, req.DeviceCode)
	case GrantTokenExchange:
		s.handleTokenExchangeGrant(ctx, client, tokenExchangeRequest{
			SubjectToken:       req.SubjectToken,
			SubjectTokenType:   req.SubjectTokenType,
			ActorToken:         req.ActorToken,
			ActorTokenType:     req.ActorTokenType,
			Resource:           req.Resource,
			Audience:           req.Audience,
			Scope:              req.Scope,
			RequestedTokenType: req.RequestedTokenType,
		})
	case GrantClientCredentials:
		strategy, ti, err := s.issuerForClient(client)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
			return
		}
		// client_credentials: subject IS the client, so ClientID =
		// Sub. No end-user auth event, hence no AuthTime/AMR.
		token, err := ti.Issue(ctx.Request().Context(), &Subject{
			ID: client.ID, Resources: req.Resource, ClientID: client.ID,
		}, scopes)
		if err != nil {
			s.logger.Error("token issuance failed", "strategy", strategy, "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
		s.recordTokenIssued(ctx, client.ID, strategy, client.ID)
		ctx.JSON(http.StatusOK, map[string]any{
			KeyAccessToken:   token.AccessToken,
			KeyTokenType:     token.TokenType,
			KeyExpiresIn:     token.ExpiresIn,
			KeyScope:         token.Scope,
			KeyTokenStrategy: strategy,
		})
	default:
		ctx.JSON(http.StatusBadRequest, map[string]any{
			KeyError:           ErrUnsupportedGrantType,
			KeySupportedGrants: SupportedGrants,
		})
	}
}

func (s *Server) handleUserInfo(ctx HandlerContext) {
	if err := s.requireDeps(depTokenIssuer, depUserProvider); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	tokenString := bearerToken(ctx.Request())
	if tokenString == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return
	}

	claims, _, err := s.validateAnyToken(ctx.Request().Context(), tokenString)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}

	user, err := s.userProvider.GetByID(ctx.Request().Context(), claims.Subject)
	if err != nil {
		ctx.JSON(http.StatusNotFound, errorBody(ErrUserNotFound))
		return
	}

	// OIDC profile: when the token carries "openid" scope, project the
	// user into the OIDC-standard claim shape (sub always, then claims
	// gated by scope per OIDC Core §5.4). The full User struct (with
	// non-standard fields like provider, created_at) is returned only
	// for non-OIDC tokens — pre-OIDC integrations keep working unchanged.
	if hasOpenIDScope(claims.Scopes) {
		body := projectUserInfoForOIDC(user, claims.Scopes)
		// RFC 9068 §2.2 claims passthrough on the OIDC profile: when
		// the access token carries auth_time / acr / amr (because it
		// was minted via /auth/login with a fresh user-auth event),
		// expose them on /userinfo so downstream policy can branch
		// on factor strength without re-validating the access token.
		// Empty values are omitted so legacy tokens still produce
		// the minimal {sub} response.
		if !claims.AuthTime.IsZero() {
			body["auth_time"] = claims.AuthTime.Unix()
		}
		if claims.ACR != "" {
			body["acr"] = claims.ACR
		}
		if len(claims.AMR) > 0 {
			body["amr"] = claims.AMR
		}
		ctx.JSON(http.StatusOK, body)
		return
	}

	ctx.JSON(http.StatusOK, user)
}

// projectUserInfoForOIDC returns the OIDC-standard claim set for a user
// gated by the token's scopes. OIDC Core §5.4 mapping:
//
//	openid  → sub (always)
//	email   → email, email_verified
//	profile → name, given_name, family_name, picture, preferred_username
//	address → address (object)
//	phone   → phone_number, phone_number_verified
//
// Non-standard fields on the User (provider, external_id, created_at,
// updated_at) are omitted — OIDC RPs don't expect them and including
// them would make the response shape ambiguous with the legacy
// non-OIDC response.
//
// Per-claim values come from User's first-class fields (Email, Name)
// or from Attributes when the field name matches the claim name.
// Operators control which claims are exposed via what they populate
// in the User and Attributes — there's no per-server claim allowlist
// to maintain.
func projectUserInfoForOIDC(u *User, scopes []string) map[string]any {
	out := map[string]any{"sub": u.ID}
	hasScope := func(name string) bool {
		return slices.Contains(scopes, name)
	}
	// Attributes win when both an attribute AND a first-class field
	// carry the same claim — the authenticator is the live source of
	// truth (User.Email + User.Name are caches that aren't always
	// repopulated by the login upsert path).
	emailFrom := func() string {
		if v, ok := u.Attributes["email"]; ok && v != "" {
			return v
		}
		return u.Email
	}
	nameFrom := func() string {
		if v, ok := u.Attributes["name"]; ok && v != "" {
			return v
		}
		return u.Name
	}
	if hasScope("email") {
		if v := emailFrom(); v != "" {
			out["email"] = v
		}
		if v, ok := u.Attributes["email_verified"]; ok {
			out["email_verified"] = v == "true"
		}
	}
	if hasScope("profile") {
		if v := nameFrom(); v != "" {
			out["name"] = v
		}
		for _, k := range []string{"given_name", "family_name", "picture", "preferred_username", "nickname", "locale", "zoneinfo"} {
			if v, ok := u.Attributes[k]; ok && v != "" {
				out[k] = v
			}
		}
	}
	if hasScope("address") {
		if v, ok := u.Attributes["address"]; ok && v != "" {
			out["address"] = v
		}
	}
	if hasScope("phone") {
		if v, ok := u.Attributes["phone_number"]; ok && v != "" {
			out["phone_number"] = v
		}
		if v, ok := u.Attributes["phone_number_verified"]; ok {
			out["phone_number_verified"] = v == "true"
		}
	}
	return out
}

func (s *Server) handleLogout(ctx HandlerContext) {
	var req struct {
		SessionID string `json:"session_id"`
	}
	// Body is optional — bearer-only logouts are allowed.
	_ = ctx.Bind(&req)

	bearer := bearerToken(ctx.Request())

	if req.SessionID == "" && bearer == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrSessionIDOrBearerRequired))
		return
	}

	// Capture (subject, client) for back-channel logout BEFORE
	// revoking the bearer — the post-revoke Validate call would
	// fail. We do this in a best-effort way: a malformed or
	// already-expired bearer just yields no back-channel
	// notification, never an error.
	var bcSubject, bcClientID, bcSID string
	if bearer != "" {
		if claims, _, err := s.validateAnyToken(ctx.Request().Context(), bearer); err == nil && claims != nil {
			bcSubject = claims.Subject
			bcSID = claims.SID
			if claims.ClientID != "" {
				bcClientID = claims.ClientID
			} else if len(claims.Audience) > 0 {
				bcClientID = claims.Audience[0]
			}
		}
	}

	revoked := []string{}
	if req.SessionID != "" && s.sessionMgr != nil {
		if err := s.sessionMgr.Destroy(ctx.Request().Context(), req.SessionID); err != nil {
			s.logger.Error("logout: destroy session failed", "error", err)
		} else {
			revoked = append(revoked, RevokedSession)
		}
	}
	if bearer != "" && len(s.tokenIssuers) > 0 {
		issuersHit := s.revokeAcrossIssuers(ctx.Request().Context(), bearer)
		for range issuersHit {
			revoked = append(revoked, RevokedToken)
		}
	}

	// OIDC Back-Channel Logout 1.0: notify the client in the
	// bearer's aud / client_id that this user just logged out so
	// the RP can tear down its local session. No-op when the
	// subsystem isn't wired or the client has no
	// backchannel_logout_uri declared.
	if bcSubject != "" && bcClientID != "" && s.clientStore != nil {
		if c, err := s.clientStore.Get(ctx.Request().Context(), bcClientID); err == nil && c != nil {
			// Multi-RP fan-out when the SubjectClientIndex is wired;
			// degrades to single-RP notification of the bearer's
			// client when it isn't.
			s.fanOutBackchannelLogout(ctx, c, bcSubject, bcSID)
		}
	}

	s.recordLogout(ctx, req.SessionID, revoked)

	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus:  StatusLoggedOut,
		KeyRevoked: revoked,
	})
}

func (s *Server) handleSendCode(ctx HandlerContext) {
	var req struct {
		Provider string `json:"provider"`
		Target   string `json:"target"`
	}
	if err := ctx.Bind(&req); err != nil || req.Provider == "" || req.Target == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrProviderAndTargetRequired))
		return
	}

	auth, err := s.getAuthenticator(req.Provider)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrUnsupportedProvider))
		return
	}

	sender, ok := auth.(CodeSender)
	if !ok {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrProviderDoesNotSendCodes))
		return
	}

	if err := sender.SendCode(ctx.Request().Context(), req.Target); err != nil {
		s.logger.Error("send code failed", "provider", req.Provider, "error", err)
		s.recordCodeSent(ctx, req.Provider, req.Target, false)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrSendFailed))
		return
	}

	s.recordCodeSent(ctx, req.Provider, req.Target, true)

	ctx.JSON(http.StatusOK, map[string]string{KeyStatus: StatusSent})
}

func (s *Server) handleGetClient(ctx HandlerContext) {
	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrClientStoreNotConfigured))
		return
	}

	clientID := ctx.Param("id")
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrMissingClientID))
		return
	}

	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, errorBody(ErrClientNotFound))
		return
	}

	ctx.JSON(http.StatusOK, client)
}
