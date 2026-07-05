package sso

import (
	"time"

	"golang.org/x/time/rate"

	"github.com/snaplink/sso/domains/tokenexchange"
	"github.com/snaplink/sso/internal/handler/tokengrant"
	"github.com/snaplink/sso/protocols/oauth"
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

// WithRefreshAbsoluteMaxLifetime opts into a hard ceiling on a refresh-token
// FAMILY's total age since original issuance, enforced at rotation time
// independent of the per-token TTL / idle-expiry / rotation-velocity cap the
// store already applies. A family that keeps rotating on schedule never
// re-triggers those defenses, so this closes the "stays alive forever"
// gap — once now-FamilyCreatedAt exceeds d, the next rotation attempt fails
// closed with the same invalid_grant every other refresh failure returns
// (oracle-leak collapse, AGENTS.md §3).
//
// d <= 0 (the default) disables the cap — byte-identical to today.
func WithRefreshAbsoluteMaxLifetime(d time.Duration) Option {
	return func(s *Server) { s.refreshAbsoluteMaxLifetime = d }
}

// WithMaxTokenExchangeChainLifetime opts into a hard ceiling on how old an
// RFC 8693 token-exchange delegation chain's underlying credential may be —
// measured from the subject_token's AuthTime (the original end-user login or
// SPIFFE SVID presentation), which every exchange hop propagates UNCHANGED.
// This is independent of any single hop's access-token TTL: a chain that
// keeps getting re-exchanged with fresh short-lived tokens never otherwise
// re-triggers an age check.
//
// d <= 0 (the default) disables the cap — byte-identical to today.
func WithMaxTokenExchangeChainLifetime(d time.Duration) Option {
	return func(s *Server) { s.maxTokenExchangeChainLifetime = d }
}

// WithTokenExchangePolicy wires an operator-defined tokenexchange.Policy that
// HandleTokenExchangeGrant consults on every exchange (after the hop's
// actor/scopes/resources are resolved, before anything is minted) to allow or
// deny that SPECIFIC delegation — e.g. "service A may never act on behalf of
// service B". A reference in-memory implementation is
// domains/tokenexchange/memory.Store.
//
// nil (the default) is a no-op: every hop is allowed, byte-identical to a
// build without this feature.
func WithTokenExchangePolicy(policy tokenexchange.Policy) Option {
	return func(s *Server) { s.tokenExchangePolicy = policy }
}

// WithIntrospectionSigner enables optional RFC 9701-style JWT-signed
// /token/introspect responses, reusing the server's existing signing-key
// infrastructure — pass the SAME issuer already wired via WithMetadataSigner
// / WithJARM (or any type satisfying SignMetadata); no separate key is
// minted. A wired signer only takes effect when the introspecting client
// ALSO opts in per-request via `Accept: application/token-introspection+jwt`
// — a wired-but-unrequested signer is a no-op.
//
// nil (the default) leaves every /token/introspect response byte-identical
// plain JSON.
func WithIntrospectionSigner(signer oauth.IntrospectionSigner) Option {
	return func(s *Server) { s.introspectionSigner = signer }
}

// WithIntrospectionBatch opts into accepting a `tokens` array in the
// /token/introspect request body (JSON `{"tokens":[...]}"` or repeated form
// field `tokens`) and returning an array of RFC 7662 result bodies in one
// round trip, sharing the same optional IntrospectionCache per token.
//
// maxSize caps how many tokens one request may include (a request over the
// cap is rejected with invalid_request); maxSize <= 0 uses
// oauth.DefaultMaxIntrospectBatchSize. Calling this Option is itself the
// enable signal — without it an inbound `tokens` field is ignored entirely
// and single-token behavior is byte-identical to today.
func WithIntrospectionBatch(maxSize int) Option {
	return func(s *Server) {
		s.introspectionBatchEnabled = true
		if maxSize > 0 {
			s.introspectionBatchMaxSize = maxSize
		} else {
			s.introspectionBatchMaxSize = oauth.DefaultMaxIntrospectBatchSize
		}
	}
}
