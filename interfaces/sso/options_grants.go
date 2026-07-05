package sso

import (
	"golang.org/x/time/rate"

	"github.com/snaplink/sso/internal/handler/tokengrant"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oauth/txntoken"
)

// WithCustomGrant registers an external grant handler for the given
// grant type URN. When a /token request's grant_type matches a
// registered handler, it is dispatched BEFORE the built-in grant
// switch — enabling custom grants (e.g. SAML2 Bearer Assertion,
// JWT Bearer, CDR/Open Banking) without forking the codebase.
//
// The handler receives the already-authenticated client, the parsed
// request, and sender-constraint thumbprints; it MUST write its own
// response on every path.
//
// Multiple calls for the same grant type replace the previous handler.
// Panics when handler is nil.
func WithCustomGrant(handler oauth.GrantHandler) Option {
	return func(s *Server) {
		if handler == nil {
			panic("sso: WithCustomGrant requires a non-nil GrantHandler")
		}
		if s.customGrantHandlers == nil {
			s.customGrantHandlers = make(map[string]oauth.GrantHandler)
		}
		s.customGrantHandlers[handler.GrantType()] = handler
	}
}

// WithJWTBearerGrant enables the RFC 7523 JWT Bearer Token Grant by wiring
// an assertion validator. When wired, clients can exchange an externally-
// signed JWT assertion for an access token at /token using
// grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer.
//
// The validator must validate the assertion's signature (against the server's
// configured trust anchor), expiry, issuer, audience, and subject. On success
// it returns (issuer, subject, nil). Every failure collapses to invalid_grant
// (oracle-leak hardening).
//
// Nil validator is a no-op (the grant stays disabled).
func WithJWTBearerGrant(validator tokengrant.JWTAssertionValidator) Option {
	return func(s *Server) {
		if validator == nil {
			return
		}
		s.jwtBearerValidator = validator
	}
}

// WithGrantTypeRateLimit configures a per-grant-type token bucket that
// limits how many /token requests of the given grant_type pass through
// per second, with the given burst size. This is distinct from the
// global HTTP-level rate limiter (WithRateLimit) which keys by client
// IP — this one keys by grant type URN and runs AFTER client
// authentication, so a flood of client_credentials can't starve the
// authorization_code bucket.
//
// rate is tokens per second (0 disallows all, negative unlimited).
// burst is the maximum accumulated tokens. Use WithRateLimit for
// per-IP throttling; use this for per-grant-type fairness.
//
// Example: limit client_credentials to 500/s burst 100, auth_code to
// 50/s burst 20.
//
//	s.WithGrantTypeRateLimit("client_credentials", 500, 100)
//	s.WithGrantTypeRateLimit("authorization_code", 50, 20)
func WithGrantTypeRateLimit(grantType string, tokensPerSec float64, burst int) Option {
	return func(s *Server) {
		if s.grantRateLimiters == nil {
			s.grantRateLimiters = make(map[string]*rateLimiterEntry)
		}
		var lim *rate.Limiter
		if tokensPerSec >= 0 {
			lim = rate.NewLimiter(rate.Limit(tokensPerSec), burst)
		}
		s.grantRateLimiters[grantType] = &rateLimiterEntry{limiter: lim}
	}
}

// WithTransactionTokens opts into RFC 9321 OAuth 2.0 Transaction Tokens: a
// short-lived, workload-identity-bound token minted from an inbound access
// token (or, for a further hop, from a previously-issued Txn-Token) that a
// downstream microservice within the same trust domain verifies LOCALLY
// (signature + exp + aud) with no round trip back to this server.
//
// It reuses the EXISTING RFC 8693 token-exchange grant + /token endpoint —
// a request is routed here only when requested_token_type names
// txntoken.TokenType; every other requested_token_type is unaffected and
// keeps flowing through the ordinary token-exchange handler.
//
//   - issuer mints the Txn-Token (see txntoken.NewIssuer). Required.
//   - validator re-validates a Txn-Token presented as a NESTED
//     subject_token, so a multi-hop internal call chain stays auditable —
//     each hop prepends its own requesting client_id onto the `act`
//     chain, mirroring the RFC 8693 §4.1.1 act-chain prepend the ordinary
//     token-exchange grant already performs. nil validator still allows
//     first-hop minting (from an ordinary access token); only chaining
//     from an existing Txn-Token is refused (fail-closed, invalid_grant —
//     never a panic).
//
// nil issuer is a no-op — the feature stays entirely OFF, byte-identical
// to a build without this package: a requested_token_type naming the
// Txn-Token URN falls through to the ordinary token-exchange handler's
// existing invalid_request collapse for an unrecognized type.
func WithTransactionTokens(issuer *txntoken.Issuer, validator *txntoken.Validator) Option {
	return func(s *Server) {
		if issuer == nil {
			return
		}
		s.txnTokenIssuer = issuer
		s.txnTokenValidator = validator
	}
}
