package sso

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/snaplink/sso/internal/handler/tokengrant"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/fapi"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// idempotentResponseWriter wraps http.ResponseWriter to capture the
// response body for idempotency caching.
type idempotentResponseWriter struct {
	http.ResponseWriter
	key        string
	cache      IdempotentCache
	body       []byte
	statusCode int
}

func (w *idempotentResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *idempotentResponseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	if err == nil && w.statusCode == http.StatusOK && w.key != "" && w.cache != nil {
		w.body = append(w.body, b...)
	}
	return n, err
}

func (s *Server) handleToken(ctx HandlerContext) {
	// RFC 6749 §5.1: token responses (success AND error) MUST carry
	// Cache-Control: no-store + Pragma: no-cache so intermediaries never
	// retain credentials. Set BEFORE any response body is written.
	tokenNoStoreHeaders(ctx)

	// Idempotency check: when an Idempotency-Key header is present
	// AND we have a cached response, return it directly without
	// processing the grant — safe retry semantics.
	var idemKey string
	var idemRW *idempotentResponseWriter
	if s.idempotentCache != nil {
		idemKey = ctx.Request().Header.Get("Idempotency-Key")
		if idemKey != "" {
			if cached, ok, _ := s.idempotentCache.Get(ctx.Request().Context(), idemKey); ok && len(cached) > 0 {
				w := ctx.ResponseWriter()
				w.Header().Set(HeaderContentType, ContentTypeJSON)
				w.WriteHeader(http.StatusOK)
				w.Write(cached)
				return
			}
			idemRW = &idempotentResponseWriter{
				ResponseWriter: ctx.ResponseWriter(),
				key:            idemKey,
				cache:          s.idempotentCache,
			}
			// Override the ResponseWriter on the underlying core.Context
			// so that ctx.JSON() writes through our capture wrapper.
			if c, ok := ctx.(*core.Context); ok {
				c.SetResponseWriter(idemRW)
			}
		}
	}

	if err := s.requireDeps(DepTokenIssuer, DepClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	var req oauth.TokenRequest
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}

	client, basicAuthUsed, handled := s.authenticateTokenClient(ctx, &req)
	if handled {
		return
	}

	// Data-residency WRITE-gate for token issuance: closes the grant-side
	// hole so a refresh/exchange/CIBA/device/code mint can't issue fresh
	// credentials for a region-constrained tenant from a disallowed serving
	// region. Checked once before the grant switch so it applies uniformly;
	// byte-identical when residency is unwired.
	if s.residencyGateTokenGrant(ctx, client) {
		return
	}

	dpopJKT, mtlsX5T, handled := s.captureSenderConstraint(ctx)
	if handled {
		return
	}

	if s.enforceFAPITokenRules(ctx, req, basicAuthUsed, dpopJKT, mtlsX5T) {
		return
	}

	// RFC 6749 §5.2 / RFC 8693 §4.5: when a client declares GrantTypes the AS
	// MUST reject any grant not in the list. Empty = unrestricted (backward compat).
	if len(client.GrantTypes) > 0 && !slices.Contains(client.GrantTypes, req.GrantType) {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrUnauthorizedClient))
		return
	}

	s.dispatchTokenGrant(ctx, client, req, dpopJKT, mtlsX5T)

	// Cache the response body for idempotency on success.
	if idemRW != nil && len(idemRW.body) > 0 {
		if idemRW.statusCode == http.StatusOK {
			_ = s.idempotentCache.Set(ctx.Request().Context(), idemKey, idemRW.body, 0)
		}
	}
}

// dispatchTokenGrant routes the authenticated, sender-constraint-captured token
// request to the per-grant handler. scopes are split here (shared by the code +
// client-credentials grants). An unknown grant_type returns 400
// unsupported_grant_type. Reached ONLY after every gate in handleToken passed.
func (s *Server) dispatchTokenGrant(ctx HandlerContext, client *Client, req oauth.TokenRequest, dpopJKT, mtlsX5T string) {
	var scopes []string
	if req.Scope != "" {
		scopes = strings.Split(req.Scope, " ")
	}

	// Custom grant handlers (registered via WithCustomGrant) take
	// priority over the built-in switch — enabling third-party grant
	// types without forking the codebase.
	if s.dispatchCustomGrant(ctx, client, req, dpopJKT, mtlsX5T) {
		return
	}

	// Per-grant-type rate limiting — checked before the built-in switch
	// so all grants are covered uniformly.
	if s.checkGrantRateLimit(ctx, req.GrantType) {
		return
	}

	switch req.GrantType {
	case GrantAuthorizationCode:
		s.handleAuthCodeTokenGrant(ctx, client, req, scopes, dpopJKT, mtlsX5T)
	case GrantRefreshToken:
		s.handleRefreshTokenGrant(ctx, client, req.RefreshToken, req.Scope, dpopJKT, mtlsX5T)
	case GrantDeviceCode:
		s.handleDeviceTokenGrant(ctx, client, req.DeviceCode, dpopJKT, mtlsX5T)
	case GrantCIBA:
		s.handleCIBATokenGrant(ctx, client, req.AuthReqID, dpopJKT, mtlsX5T)
	case GrantTokenExchange:
		s.handleTokenExchangeGrant(ctx, client, buildTokenExchangeRequest(req, dpopJKT, mtlsX5T))
	case GrantClientCredentials:
		// RFC 6749 §4.4: only confidential clients may use this grant.
		if s.denyPublicClientCredentials(ctx, client, req) {
			return
		}
		tokengrant.HandleClientCredentialsGrant(s, ctx, client, scopes, req.Resource, dpopJKT, mtlsX5T)
	default:
		ctx.JSON(http.StatusBadRequest, map[string]any{
			KeyError:           ErrUnsupportedGrantType,
			KeySupportedGrants: SupportedGrants,
		})
	}
}

// buildTokenExchangeRequest maps the parsed /token parameters onto the RFC 8693
// token-exchange request, threading the captured RFC 9449 DPoP / RFC 8705 mTLS
// sender-constraint thumbprints so the exchanged token is cnf-bound like every
// other issuance grant. Kept out of dispatchTokenGrant to hold that switch within
// the function-length budget.
func buildTokenExchangeRequest(req oauth.TokenRequest, dpopJKT, mtlsX5T string) tokengrant.TokenExchangeRequest {
	return tokengrant.TokenExchangeRequest{
		SubjectToken:       req.SubjectToken,
		SubjectTokenType:   req.SubjectTokenType,
		ActorToken:         req.ActorToken,
		ActorTokenType:     req.ActorTokenType,
		Resource:           req.Resource,
		Audience:           req.Audience,
		Scope:              req.Scope,
		RequestedTokenType: req.RequestedTokenType,
		ACRValues:          req.ACRValues,
		DPoPJKT:            dpopJKT,
		MTLSX5T:            mtlsX5T,
	}
}

// resolveAssertedClientID applies RFC 7521 §4.2 + RFC 7523 §2.2 JWT-bearer
// client authentication when the request carries a client_assertion. The JWT
// replaces client_secret as proof of identity: it MUST be signed by a key in
// Client.JWKS; iss / sub MUST equal the client_id; aud MUST include the AS
// issuer or token endpoint URL; exp MUST be in the future. Replay defense (jti
// tracking) reuses the security.JTIReplayStore wiring JAR already opts into. On
// success req.ClientID is overwritten with the asserted id. Returns true
// (handled) when a response was ALREADY written; the caller MUST then stop.
func (s *Server) resolveAssertedClientID(ctx HandlerContext, req *oauth.TokenRequest) bool {
	if req.ClientAssertion == "" && req.ClientAssertionType == "" {
		return false
	}
	if req.ClientAssertionType != ClientAssertionTypeJWTBearer {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return true
	}
	assertedID, err := verifyJWTClientAssertion(
		ctx.Request().Context(),
		req.ClientAssertion,
		req.ClientID,
		s.clientStore,
		s.resolveIssuer(ctx),
		s.jtiReplayStore,
		s.jtiReplayFailClosed,
	)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return true
	}
	req.ClientID = assertedID
	return false
}

// authenticateTokenClient runs the client-identification + authentication
// gate ladder (assertion -> lookup -> tenant -> secret -> resource) and
// returns the resolved client plus whether HTTP Basic creds were used. When
// handled==true a response has ALREADY been written and the caller MUST return
// immediately. Gate order is load-bearing: tenant precedes secret precedes
// resource, and every failure collapses to its oracle-safe wire code.
func (s *Server) authenticateTokenClient(ctx HandlerContext, req *oauth.TokenRequest) (client *Client, basicAuthUsed bool, handled bool) {
	// HTTP Basic auth takes precedence over body fields per RFC 6749 §2.3.1.
	if id, secret, ok := basicClientCreds(ctx.Request()); ok {
		req.ClientID = id
		req.ClientSecret = secret
		basicAuthUsed = true
	}

	if s.resolveAssertedClientID(ctx, req) {
		return nil, basicAuthUsed, true
	}

	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return nil, basicAuthUsed, true
	}
	if !clientTenantOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, errorBody(ErrTenantMismatch))
		return nil, basicAuthUsed, true
	}
	// Skip the client_secret check when the caller authenticated
	// via JWT assertion — Client.JWKS verification stands in for
	// the secret. RFC 7521 §4.2 prohibits requiring BOTH proofs.
	if req.ClientAssertion == "" {
		if err := s.clientStore.ValidateSecret(ctx.Request().Context(), req.ClientID, req.ClientSecret); err != nil {
			// RFC 6749 §5.2: all client-authentication failures return
			// invalid_client. Collapsing wrong-secret into the same code as
			// unknown-client (above) is also oracle-safe — a distinct
			// invalid_client_secret would let an attacker enumerate valid
			// client_ids by the error code alone.
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
			return nil, basicAuthUsed, true
		}
	}
	// RFC 8707 §2: each requested `resource` MUST be allowlisted on
	// the client. Empty allowlist disables enforcement (legacy compat).
	if !client.AreResourcesAllowed(req.Resource) {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidTarget))
		return nil, basicAuthUsed, true
	}

	return client, basicAuthUsed, false
}

// captureSenderConstraint validates an optional DPoP proof and/or extracts an
// mTLS client-cert thumbprint, returning the resulting JKT / x5t#S256 so the
// grant branches can sender-constrain the minted token. When handled==true a
// response (the DPoP failure path) has ALREADY been written and the caller MUST
// return immediately.
func (s *Server) captureSenderConstraint(ctx HandlerContext) (dpopJKT, mtlsX5T string, handled bool) {
	// RFC 9449 — DPoP. When the request carries a `DPoP` header,
	// validate the proof and stash the resulting JKT so the grant
	// branches below can bind the issued access token to the key.
	// Absence of the header keeps the legacy bearer-token path —
	// DPoP is opt-in per request, never required by this server.
	if proof := ctx.Request().Header.Get(HeaderDPoP); proof != "" {
		binding, err := verifyDPoPProof(
			ctx.Request().Context(),
			proof,
			ctx.Request().Method,
			requestURLForDPoP(ctx.Request()),
			s.jtiReplayStore,
			s.jtiReplayFailClosed,
			s.dpopNonceProvider,
			s.resolvedDPoPProofMaxAge(),
			s.resolvedDPoPProofClockSkew(), "", // issuance: no access token yet, no ath
		)
		if err != nil {
			// RFC 9449 §8 — nonce required: stamp a fresh nonce on
			// the response and respond with use_dpop_nonce instead
			// of invalid_dpop_proof so clients can retry. AS-side
			// uses HTTP 400 (vs 401 for RS-side).
			if errors.Is(err, ErrDPoPNonceRequired) {
				s.stampDPoPNonce(ctx)
				s.logger.Info("dpop nonce challenge", "method", ctx.Request().Method)
				ctx.JSON(http.StatusBadRequest, errorBody(ErrUseDPoPNonce))
				return "", "", true
			}
			s.logger.Error("dpop proof failed", "error", err)
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidDPoPProof))
			return "", "", true
		}
		dpopJKT = binding.JKT
	}

	// RFC 8705 §3 — mTLS certificate-bound access tokens. When a
	// client cert extractor is wired AND the inbound request
	// carries a client cert, stamp the cert's SHA-256 thumbprint
	// into the token's cnf.x5t#S256 claim. Mutually exclusive
	// with DPoP — first-set wins (caller MUST NOT supply both,
	// the configuration is per-token).
	if s.clientCertExtractor != nil {
		if cert, ok := s.clientCertExtractor.ExtractClientCert(ctx.Request()); ok && cert != nil {
			mtlsX5T = certificateThumbprintS256(cert)
		}
	}

	return dpopJKT, mtlsX5T, false
}

// enforceFAPITokenRules applies the FAPI 2.0 Security Profile token gate.
// Returns true (handled) only when enforce mode rejected the request — a
// response was ALREADY written and the caller MUST return immediately.
// Inspection mode audits and returns false so the grant proceeds.
func (s *Server) enforceFAPITokenRules(ctx HandlerContext, req oauth.TokenRequest, basicAuthUsed bool, dpopJKT, mtlsX5T string) bool {
	// FAPI 2.0 Security Profile — issued access tokens MUST be
	// sender-constrained via DPoP or mTLS. Checked once here, before
	// the grant switch, so it applies uniformly to every grant that
	// mints an access token. Inspection mode audits and proceeds;
	// enforce mode rejects with invalid_request (a bearer-only token
	// request is the violation, not a credential failure — no oracle
	// concern). The rule id lands in the audit event; the wire stays
	// the standard error code.
	if !s.fapiValidator.Active() {
		return false
	}
	// Classify the client-auth method ACTUALLY used. A mere mTLS binding cert
	// (mtlsX5T) is NOT ClientAuthTLS: the server implements only RFC 8705 §3
	// binding, never §2 tls_client_auth, so counting its presence as TLS auth let
	// a Basic/secret client be misclassified as FAPI-compliant and bypass the
	// shared-secret rejection. The cert still drives SenderConstrained below.
	clientAuthMethod := fapi.ClientAuthNone
	switch {
	case req.ClientAssertion != "":
		clientAuthMethod = fapi.ClientAuthPrivateKeyJWT
	case basicAuthUsed:
		clientAuthMethod = fapi.ClientAuthSecretBasic
	case req.ClientSecret != "":
		clientAuthMethod = fapi.ClientAuthSecretPost
	}
	vs := s.fapiValidator.CheckToken(fapi.TokenContext{
		ClientID:          req.ClientID,
		GrantType:         req.GrantType,
		SenderConstrained: dpopJKT != "" || mtlsX5T != "",
		ClientAuthMethod:  clientAuthMethod,
	})
	if len(vs) == 0 {
		return false
	}
	mode := s.fapiValidator.Mode().String()
	for _, v := range vs {
		audit.RecordFAPIViolation(s.auditor, ctx, v.ClientID, v.RuleID, v.Detail, mode)
		if s.metrics != nil {
			s.metrics.FAPIViolationsTotal.WithLabelValues(v.RuleID, mode).Inc()
		}
	}
	if s.fapiValidator.Enforcing() {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return true
	}
	return false
}

// The per-grant handlers below are thin wrappers: *Server satisfies the
// handler.*GrantDeps interfaces via accessors_token_grant.go, and the grant
// orchestration lives in internal/handler (the only tier that may import BOTH
// oauth — code/refresh stores — AND oidc — id_token issuance).

// dispatchCustomGrant checks the custom grant handler registry and dispatches
// to a registered GrantHandler if one matches the request's grant_type.
// Returns true (response already written) when a handler matched.
func (s *Server) dispatchCustomGrant(ctx HandlerContext, client *Client, req oauth.TokenRequest, dpopJKT, mtlsX5T string) bool {
	if len(s.customGrantHandlers) == 0 {
		return false
	}
	handler, ok := s.customGrantHandlers[req.GrantType]
	if !ok {
		return false
	}
	handler.Handle(ctx, client, req, dpopJKT, mtlsX5T)
	return true
}

// checkGrantRateLimit checks the per-grant-type rate limiter for the given
// grant type. Returns true (response already written) when the rate limit
// was exceeded.
func (s *Server) checkGrantRateLimit(ctx HandlerContext, grantType string) bool {
	entry, ok := s.grantRateLimiters[grantType]
	if !ok || entry == nil || entry.limiter == nil {
		return false
	}
	if !entry.limiter.Allow() {
		ctx.JSON(http.StatusTooManyRequests, errorBody(ErrUnsupportedGrantType))
		return true
	}
	return false
}

// denyPublicClientCredentials gates client_credentials to confidential
// clients only (RFC 6749 §4.4). Returns true when the request should
// be denied and a response has been written.
func (s *Server) denyPublicClientCredentials(ctx HandlerContext, client *Client, req oauth.TokenRequest) bool {
	if client.Secret == "" && req.ClientAssertion == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return true
	}
	return false
}

// handleAuthCodeTokenGrant delegates the authorization_code token exchange.
func (s *Server) handleAuthCodeTokenGrant(ctx HandlerContext, client *Client, req oauth.TokenRequest, scopes []string, dpopJKT, mtlsX5T string) {
	tokengrant.HandleAuthCodeGrant(s, ctx, client, req, scopes, dpopJKT, mtlsX5T)
}

// handleRefreshTokenGrant delegates the RFC 6749 §6 refresh_token grant (the
// refresh-family / rotation-velocity primitives are implemented in root).
func (s *Server) handleRefreshTokenGrant(ctx HandlerContext, client *Client, refreshToken, scope, dpopJKT, mtlsX5T string) {
	tokengrant.HandleRefreshGrant(s, ctx, client, refreshToken, scope, dpopJKT, mtlsX5T)
}

// handleCIBATokenGrant delegates the OIDC CIBA poll/ping token grant.
func (s *Server) handleCIBATokenGrant(ctx HandlerContext, client *Client, authReqID, dpopJKT, mtlsX5T string) {
	tokengrant.HandleCIBAGrant(s, ctx, client, authReqID, dpopJKT, mtlsX5T)
}

// handleTokenExchangeGrant delegates the RFC 8693 token-exchange grant (the
// SPIFFE / JTI-replay primitives + Native SSO device-secret sub-exchange are in
// root).
func (s *Server) handleTokenExchangeGrant(ctx HandlerContext, client *Client, req tokengrant.TokenExchangeRequest) {
	tokengrant.HandleTokenExchangeGrant(s, ctx, client, req)
}

// mergeTargets merges resource + audience indicators (RFC 8693 + RFC 8707) into a
// single deduplicated, in-order target list. Retained in root because the Native
// SSO device-secret exchange (server_native_sso.go) also uses it.
func mergeTargets(primary, secondary []string) []string {
	return oauth.MergeTargets(primary, secondary)
}
