package sso

import (
	"golang.org/x/time/rate"

	"github.com/snaplink/sso/internal/handler/tokengrant"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/security"
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

// WithWorkloadIdentityProviders accepts one or more cloud workload-identity
// tokens (AWS/GCP/Azure) as /token client authentication, in place of a
// client_secret or private_key_jwt — the cloud analog of WithSPIFFEJWTSVID,
// but wired as a client-auth method rather than a token-exchange
// subject_token. Today only security.NewGCPWorkloadIdentityValidator ships;
// AWS/Azure are documented follow-ups (see the securityverify package doc).
//
// A client opts in per-registration by setting TokenEndpointAuthMethod to
// ClientAuthWorkloadIdentity and populating two Client.Attributes:
//
//   - security.AttrWorkloadIdentityProvider — which registered provider's
//     Name() to use ("gcp").
//   - security.AttrWorkloadIdentitySubject — the EXPECTED verified
//     WorkloadIdentity.Subject (e.g. a GCP service-account email). This is
//     the security crux: it is what stops any OTHER workload the cloud
//     provider will happily vouch for from impersonating THIS client.
//
// The request then presents the cloud-issued token as client_assertion with
// client_assertion_type=ClientAssertionTypeWorkloadIdentity (RFC 7521 §4.2
// shape, reusing the SAME two wire fields private_key_jwt already binds —
// no new endpoint, no new param).
//
// Multiple calls accumulate providers (keyed by Name()); registering the
// same name twice replaces the previous one. No call at all (the default)
// leaves the feature entirely off: ClientAuthWorkloadIdentity then never
// succeeds, byte-identical to today.
func WithWorkloadIdentityProviders(providers ...security.WorkloadIdentityProvider) Option {
	return func(s *Server) {
		if s.workloadIdentityProviders == nil {
			s.workloadIdentityProviders = make(map[string]security.WorkloadIdentityProvider, len(providers))
		}
		for _, p := range providers {
			if p == nil || p.Name() == "" {
				continue
			}
			s.workloadIdentityProviders[p.Name()] = p
		}
	}
}
