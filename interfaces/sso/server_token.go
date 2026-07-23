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
	"github.com/snaplink/sso/protocols/oauth/txntoken"
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

	idemKey, idemRW, served := s.beginTokenIdempotency(ctx)
	if served {
		return
	}

	if err := s.requireDeps(DepTokenIssuer, DepClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrServerMisconfigured))
		return
	}

	var req oauth.TokenRequest
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidRequest))
		return
	}

	client, basicAuthUsed, handled := s.authenticateTokenClient(ctx, &req)
	if handled {
		return
	}

	// Data-residency WRITE-gate for token issuance (see
	// residencyGateTokenGrant): checked once before the grant switch so it
	// applies uniformly; byte-identical when residency is unwired.
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

	if s.rejectDisallowedGrantType(ctx, client, req.GrantType) {
		return
	}

	s.dispatchTokenGrant(ctx, client, req, dpopJKT, mtlsX5T)
	s.finishTokenIdempotency(ctx, idemKey, idemRW)
}

// beginTokenIdempotency implements the Idempotency-Key fast path: when the
// header names an already-cached response it is replayed verbatim
// (served=true, the caller MUST return); otherwise the context's
// ResponseWriter is swapped for a capture wrapper so finishTokenIdempotency
// can cache the eventual success body — safe retry semantics.
func (s *Server) beginTokenIdempotency(ctx HandlerContext) (idemKey string, idemRW *idempotentResponseWriter, served bool) {
	if s.idempotentCache == nil {
		return "", nil, false
	}
	idemKey = ctx.Request().Header.Get("Idempotency-Key")
	if idemKey == "" {
		return "", nil, false
	}
	if cached, ok, _ := s.idempotentCache.Get(ctx.Request().Context(), idemKey); ok && len(cached) > 0 {
		w := ctx.ResponseWriter()
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		w.Write(cached)
		return idemKey, nil, true
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
	return idemKey, idemRW, false
}

// finishTokenIdempotency caches the captured response body for idempotent
// replay — success (200) responses only.
func (s *Server) finishTokenIdempotency(ctx HandlerContext, idemKey string, idemRW *idempotentResponseWriter) {
	if idemRW != nil && len(idemRW.body) > 0 {
		if idemRW.statusCode == http.StatusOK {
			_ = s.idempotentCache.Set(ctx.Request().Context(), idemKey, idemRW.body, 0)
		}
	}
}

// rejectDisallowedGrantType enforces RFC 6749 §5.2 / RFC 8693 §4.5: when a
// client declares GrantTypes the AS MUST reject any grant not in the list.
// Empty = unrestricted (backward compat). Returns true when the 400
// unauthorized_client response was written and the caller MUST return.
func (s *Server) rejectDisallowedGrantType(ctx HandlerContext, client *Client, grantType string) bool {
	if len(client.GrantTypes) > 0 && !slices.Contains(client.GrantTypes, grantType) {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrUnauthorizedClient))
		return true
	}
	return false
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

	// Token-policy engine (opt-in): block dangerous scope combos (no-op unwired).
	if s.denyTokenScopeCombo(ctx, client.ID, scopes) {
		return
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
		s.dispatchTokenExchangeOrTxnToken(ctx, client, req, dpopJKT, mtlsX5T)
	case GrantClientCredentials:
		// RFC 6749 §4.4: only confidential clients may use this grant.
		if s.denyPublicClientCredentials(ctx, client, req) {
			return
		}
		tokengrant.HandleClientCredentialsGrant(s, ctx, client, scopes, req.Resource, dpopJKT, mtlsX5T)
	case GrantJWTBearer:
		s.handleJWTBearerGrant(ctx, client, req, scopes, dpopJKT, mtlsX5T)
	default:
		ctx.JSON(http.StatusBadRequest, map[string]any{
			KeyError:           ErrUnsupportedGrantType,
			KeySupportedGrants: SupportedGrants,
		})
	}
}

// dispatchTokenExchangeOrTxnToken routes a grant_type=token-exchange request
// to the RFC 9321 Transaction Token mint OR the ordinary RFC 8693 exchange
// handler, distinguished only by requested_token_type. Extracted from
// dispatchTokenGrant's switch to hold that function within budget.
//
// s.txnTokenIssuer is nil unless WithTransactionTokens was called, so an
// unconfigured server is byte-identical: the request falls through and the
// ordinary handler's requested_token_type allowlist rejects an unrecognized
// value exactly as it does today.
func (s *Server) dispatchTokenExchangeOrTxnToken(ctx HandlerContext, client *Client, req oauth.TokenRequest, dpopJKT, mtlsX5T string) {
	if s.txnTokenIssuer != nil && req.RequestedTokenType == txntoken.TokenType {
		s.handleTransactionTokenGrant(ctx, client, req)
		return
	}
	s.handleTokenExchangeGrant(ctx, client, buildTokenExchangeRequest(req, dpopJKT, mtlsX5T))
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
				ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrUseDPoPNonce))
				return "", "", true
			}
			s.logger.Error("dpop proof failed", "error", err)
			ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidDPoPProof))
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
	// FAPI §5.3.3: check client assertion signing alg against the allowlist.
	vs = append(vs, s.fapiFAPIClientAssertionAlgCheck(req)...)
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
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidRequest))
		return true
	}
	return false
}

// fapiFAPIClientAssertionAlgCheck extracts the alg from the client assertion
// JWT (if present) and checks it against the FAPI allowlist. Extracted to keep
// enforceFAPITokenRules under the function-length budget.
func (s *Server) fapiFAPIClientAssertionAlgCheck(req oauth.TokenRequest) []fapi.Violation {
	if req.ClientAssertion == "" {
		return nil
	}
	clientAssertionAlg := fapi.ExtractJWTAlg(req.ClientAssertion)
	return s.fapiValidator.CheckSigningAlg(fapi.SigningAlgContext{
		ClientID:           req.ClientID,
		ClientAssertionAlg: clientAssertionAlg,
	})
}

// The per-grant handlers below are thin wrappers: *Server satisfies the
// handler.*GrantDeps interfaces via accessors_token_grant.go, and the grant
// orchestration lives in internal/handler (the only tier that may import BOTH
// oauth — code/refresh stores — AND oidc — id_token issuance).

// JWT Bearer Grant (RFC 7523) wrapper.
func (s *Server) handleJWTBearerGrant(ctx HandlerContext, client *Client, req oauth.TokenRequest, scopes []string, dpopJKT, mtlsX5T string) {
	tokengrant.HandleJWTBearerGrant(s, ctx, client, req.Assertion, scopes, req.Resource, dpopJKT, mtlsX5T)
}

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
		ctx.JSON(http.StatusTooManyRequests, errorBody(ctx, ErrUnsupportedGrantType))
		return true
	}
	return false
}

// denyPublicClientCredentials gates client_credentials to confidential
// clients only (RFC 6749 §4.4). Returns true when the request should
// be denied and a response has been written.
//
// By the time this runs, authenticateTokenClient has ALREADY succeeded (a
// failed auth returns earlier) — so a client registered for tls_client_auth
// or self_signed_tls reaching here proves it authenticated via mTLS (RFC
// 8705 §2), which needs no client_secret at all by design. Checking only
// Secret/ClientAssertion would misclassify that client as public and reject
// every mTLS-only client_credentials request.
func (s *Server) denyPublicClientCredentials(ctx HandlerContext, client *Client, req oauth.TokenRequest) bool {
	usingMTLS := client.TokenEndpointAuthMethod == ClientAuthTLS || client.TokenEndpointAuthMethod == ClientAuthSelfSignedTLS
	if client.Secret == "" && req.ClientAssertion == "" && !usingMTLS {
		ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrInvalidClient))
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

// handleTransactionTokenGrant delegates the RFC 9321 Transaction Token mint.
// Reached ONLY when WithTransactionTokens wired an Issuer AND the request's
// requested_token_type names the Txn-Token URN (see dispatchTokenGrant).
func (s *Server) handleTransactionTokenGrant(ctx HandlerContext, client *Client, req oauth.TokenRequest) {
	txntoken.HandleGrant(s, s.txnTokenIssuer, s.txnTokenValidator, ctx, client, buildTxnTokenRequest(req))
}

// buildTxnTokenRequest maps the parsed /token parameters onto the RFC 9321
// Transaction Token request. Kept alongside buildTokenExchangeRequest for
// the same reason: hold dispatchTokenGrant within the function-length budget.
func buildTxnTokenRequest(req oauth.TokenRequest) txntoken.Request {
	return txntoken.Request{
		SubjectToken:     req.SubjectToken,
		SubjectTokenType: req.SubjectTokenType,
		Audience:         req.Audience,
		Purpose:          req.Purp,
		RequestContext:   req.RequestContext,
	}
}

// var _ txntoken.Deps = (*Server)(nil) proves *Server satisfies HandleGrant's
// dependency interface via ValidateAnyToken (accessors_handlers.go),
// RecordTokenIssued (accessors_handlers.go), and SrvLogger (accessors.go).
var _ txntoken.Deps = (*Server)(nil)

// JWTBearerAssertionValidator returns the RFC 7523 JWT Bearer assertion
// validator, or nil when the grant is not enabled. Relocated from
// accessors_handlers.go (which was at the line budget).
func (s *Server) JWTBearerAssertionValidator() tokengrant.JWTAssertionValidator {
	return s.jwtBearerValidator
}

// SAML2AssertionValidator returns the RFC 7522 SAML 2.0 Bearer assertion
// validator, or nil when the grant is not enabled.
func (s *Server) SAML2AssertionValidator() tokengrant.SAMLAssertionValidator {
	return s.saml2BearerValidator
}
