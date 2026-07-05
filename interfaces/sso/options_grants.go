package sso

import (
	"context"
	"time"

	"golang.org/x/time/rate"

	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/domains/tokenexchange"
	"github.com/snaplink/sso/domains/tokenexchange/agentidentity"
	"github.com/snaplink/sso/internal/handler/tokengrant"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oauth/txntoken"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/i18n"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

// WithDomainVerificationResolver injects the DNS-TXT resolver used by the admin
// connection email-domain verification endpoint (first-class DI so tests run
// network-free with a fake and operators can supply a DNS-over-HTTPS resolver).
// Nil/unset uses the stdlib-backed production resolver. This only affects the
// resolver; the enable flag + record prefix live on the connections.Store
// (WithDomainVerificationRequired / config connections.domain_verification).
// Relocated from options_admin.go, then from options_httpstack.go (which ran
// out of room adding WithWASMAuthzEngine), to keep both files within budget;
// the DomainResolver() accessor that reads this field stays in
// options_httpstack.go beside ConditionalAccessStore().
func WithDomainVerificationResolver(r connections.DNSResolver) Option {
	return func(s *Server) {
		if r != nil {
			s.domainVerificationResolver = r
		}
	}
}

// WithLocalizer opts into error-response localization: when set, the
// authorization-endpoint error envelope (authzErrorBody / authzErrorBodyDesc,
// used by /auth/login and every other authorization-response error path — see
// server_discovery.go) adds an error_description_localized field alongside
// the existing error / error_description. The locale is the top-quality tag
// from the request's Accept-Language header, falling back to whatever
// platform/geo already resolved as this request's recommended_language — the
// two mechanisms share one signal rather than compete (see shared/i18n
// package doc).
//
// nil (the default) is a byte-identical no-op: Accept-Language is never even
// read, and no wire field is added. A configured Localizer with no
// translation for a given (code, locale) is likewise silent — the response
// is the SAME as if no Localizer were wired. Use i18n.NewDefaultLocalizer for
// the small demonstration en/es bundle, or i18n.NewMemoryLocalizer /
// i18n.LoadBundles over your own catalog. Relocated from options_misc.go to
// keep that file within the per-file line budget.
func WithLocalizer(l i18n.Localizer) Option {
	return func(s *Server) { s.localizer = l }
}

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

// WithExternalUserStore wires the cross-tenant B2B collaboration guest-record
// store (domains/tenant.ExternalUserStore) — the lightweight pointer
// registering that a user who natively belongs to another tenant may act as
// a guest of a client's tenant, without duplicating that user's record. A
// reference in-memory implementation is domains/tenant/memory.
//
// This gate (tokExEnforceTenantCollaboration) only activates once BOTH this
// AND WithTenantCollaborationStore are wired; nil (the default, either or
// both) is a no-op — every token-exchange behaves byte-identically to a
// build without this feature.
func WithExternalUserStore(store tenant.ExternalUserStore) Option {
	return func(s *Server) { s.externalUserStore = store }
}

// WithTenantCollaborationStore wires the cross-tenant B2B collaboration
// trust allow-list (domains/tenant.CollaborationStore) — the explicit,
// opt-in record that a guest tenant accepts guest tokens whose home is a
// named other tenant. Absence of a row (or of this store entirely) is NO
// TRUST — the default, fail-closed stance (AGENTS.md §3). A reference
// in-memory implementation is domains/tenant/memory.
//
// Like WithExternalUserStore, this only takes effect once BOTH stores are
// wired; nil (the default) is a no-op.
func WithTenantCollaborationStore(store tenant.CollaborationStore) Option {
	return func(s *Server) { s.tenantCollaborationStore = store }
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

// WithOIDCSessionManagement opts into OpenID Connect Session Management 1.0:
// a `session_state` value is computed and returned on every /auth/login
// response that carries the `openid` scope, a non-HttpOnly browser-state
// cookie is stamped alongside it (cleared at /end_session), and discovery
// advertises `check_session_iframe` — the RP-embeddable OP iframe served at
// GET /check_session_iframe.
//
// Requires the OIDC feature gate to also be on (FeatureGates.OIDC); with the
// gate off, /check_session_iframe stays unmounted and discovery omits the
// field regardless of this option.
//
// Not called (the default): discovery never advertises check_session_iframe,
// /auth/login never adds session_state or the cookie, and /check_session_iframe
// 404s — byte-identical to a build predating this feature.
func WithOIDCSessionManagement() Option {
	return func(s *Server) { s.sessionManagementEnabled = true }
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

// WithWorkloadIdentityProviders accepts one or more cloud workload-identity
// tokens (AWS/GCP/Azure) as /token client authentication, in place of a
// client_secret or private_key_jwt — the cloud analog of WithSPIFFEJWTSVID,
// but wired as a client-auth method rather than a token-exchange
// subject_token. security.NewGCPWorkloadIdentityValidator and
// security.NewAWSWorkloadIdentityValidator ship today; Azure is a documented
// follow-up (see the securityverify package doc).
//
// A client opts in per-registration by setting TokenEndpointAuthMethod to
// ClientAuthWorkloadIdentity and populating two Client.Attributes:
//
//   - security.AttrWorkloadIdentityProvider — which registered provider's
//     Name() to use ("gcp", "aws").
//   - security.AttrWorkloadIdentitySubject — the EXPECTED verified
//     WorkloadIdentity.Subject (e.g. a GCP service-account email, or an AWS
//     EKS "system:serviceaccount:<namespace>:<name>" subject). This is the
//     security crux: it is what stops any OTHER workload the cloud provider
//     will happily vouch for from impersonating THIS client.
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

// WithAgentDelegationGrant enables the delegation_token grant
// (core.GrantTypeAgentDelegation, domains/tokenexchange/agentidentity): an
// AI agent redeems a previously-created, human-authorized AgentSession for
// an access token whose `sub` is the agent's own identity and whose `act`
// claim points back to the delegating human, with scopes narrowed to the
// live intersection of the agent's policy, the session's grant, and the
// human's CURRENT entitlement (never widened — see agentidentity.Deps).
//
// All three arguments are REQUIRED: unlike most opt-in gates in this
// codebase, a partially-wired delegation grant would be worse than no
// grant at all (it could only under-check the "never widen past the
// human's entitlement" guarantee this feature exists to provide), so ANY
// nil argument leaves the grant type entirely unregistered — a
// grant_type=urn:snaplink:params:oauth:grant-type:delegation request falls
// through to the ordinary unsupported_grant_type response, byte-identical
// to a build without this feature.
//
//   - provider resolves agent identities (agentidentity.AgentProvider).
//     agentidentity.NewMemoryAgentProvider is the in-process reference
//     implementation.
//   - sessions persists the bounded, revocable delegation records
//     (agentidentity.AgentSessionStore). agentidentity.NewMemoryAgentSessionStore
//     is the in-process reference implementation; revoking a session there
//     (or via agentidentity.RevokeSession / RevokeAllForHuman, which also
//     audit the action) is checked at EVERY subsequent mint attempt,
//     fail-closed.
//   - entitlements resolves a human subject's CURRENT scope entitlement,
//     called fresh on every mint (never a cached snapshot) — e.g. wrapping
//     an operator's permissions.Provider role expansion.
func WithAgentDelegationGrant(provider agentidentity.AgentProvider, sessions agentidentity.AgentSessionStore, entitlements agentidentity.EntitlementsFunc) Option {
	return func(s *Server) {
		if provider == nil || sessions == nil || entitlements == nil {
			return
		}
		h := &agentDelegationHandler{
			server:       s,
			provider:     provider,
			sessions:     sessions,
			entitlements: entitlements,
		}
		if s.customGrantHandlers == nil {
			s.customGrantHandlers = make(map[string]oauth.GrantHandler)
		}
		s.customGrantHandlers[core.GrantTypeAgentDelegation] = h
	}
}

// agentDelegationHandler is an oauth.GrantHandler that delegates to
// agentidentity.HandleGrant, satisfying agentidentity.Deps itself: the
// Mint-side capabilities (IssuerForClient, DPoPTokenTypeOr,
// RecordTokenIssued, Auditor, SrvLogger) forward to the server — every one
// of those methods already exists for the OTHER grant handlers — while
// Agents/Sessions/HumanScopes serve the three pieces WithAgentDelegationGrant
// captured, keeping *Server itself free of any new agent-identity-specific
// field or accessor.
type agentDelegationHandler struct {
	server       *Server
	provider     agentidentity.AgentProvider
	sessions     agentidentity.AgentSessionStore
	entitlements agentidentity.EntitlementsFunc
}

func (h *agentDelegationHandler) GrantType() string { return core.GrantTypeAgentDelegation }

func (h *agentDelegationHandler) Handle(ctx core.HandlerContext, client *core.Client, req oauth.TokenRequest, dpopJKT, mtlsX5T string) {
	agentidentity.HandleGrant(h, ctx, client, agentidentity.Request{
		AgentSessionID: req.AgentSessionID,
		Scope:          req.Scope,
		Resource:       req.Resource,
	}, dpopJKT, mtlsX5T)
}

func (h *agentDelegationHandler) Agents() agentidentity.AgentProvider       { return h.provider }
func (h *agentDelegationHandler) Sessions() agentidentity.AgentSessionStore { return h.sessions }

func (h *agentDelegationHandler) HumanScopes(ctx context.Context, humanSubject string) ([]string, error) {
	return h.entitlements(ctx, humanSubject)
}

func (h *agentDelegationHandler) IssuerForClient(c *core.Client) (string, core.TokenIssuer, error) {
	return h.server.IssuerForClient(c)
}

func (h *agentDelegationHandler) DPoPTokenTypeOr(defaultType, jkt string) string {
	return h.server.DPoPTokenTypeOr(defaultType, jkt)
}

func (h *agentDelegationHandler) RecordTokenIssued(ctx core.HandlerContext, clientID, strategy, subjectID string) {
	h.server.RecordTokenIssued(ctx, clientID, strategy, subjectID)
}

func (h *agentDelegationHandler) Auditor() *audit.Recorder { return h.server.Auditor() }

func (h *agentDelegationHandler) SrvLogger() spi.Logger { return h.server.SrvLogger() }

// var _ agentidentity.Deps = (*agentDelegationHandler)(nil) proves the
// wrapper satisfies HandleGrant's dependency interface.
var _ agentidentity.Deps = (*agentDelegationHandler)(nil)
