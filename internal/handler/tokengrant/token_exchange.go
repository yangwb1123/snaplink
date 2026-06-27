package tokengrant

import (
	"context"
	"net/http"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

// TokenExchangeRequest is the subset of /token parameters the RFC 8693
// token-exchange grant cares about. Pulled out of the main /token request struct
// so the grant reads cleanly; defined here (not in root) so the extracted grant
// handler can reference it without a root->handler import cycle.
type TokenExchangeRequest struct {
	SubjectToken       string
	SubjectTokenType   string
	ActorToken         string
	ActorTokenType     string
	Resource           []string
	Audience           []string
	Scope              string
	RequestedTokenType string
	// RFC 9470 step-up: caller-asserted ACR floor for the exchanged token.
	// Space-separated values; the inbound subject_token's ACR claim MUST be a
	// member of this set or the exchange fails with
	// insufficient_user_authentication. Empty = no demand (inbound ACR
	// transparently propagates as today).
	ACRValues string
}

// TokenExchangeDeps is what HandleTokenExchangeGrant needs. *sso.Server
// satisfies it via accessors_token_grant.go with a compile-time guard there.
type TokenExchangeDeps interface {
	RefreshTokenStore() oauth.RefreshTokenStore
	DeviceSecretStore() core.DeviceSecretStore
	IssuerForClient(c *core.Client) (string, core.TokenIssuer, error)
	IDTokenIssuerForClient(c *core.Client) (oidc.IDTokenIssuer, bool, error)
	ValidateAnyToken(ctx context.Context, token string) (*core.TokenClaims, string, error)
	ResolveLocalSubject(ctx context.Context, sub string) (string, error)
	ApplyPairwiseSubject(ctx context.Context, client *core.Client, localSub string) string
	IssueRefreshToken(ctx context.Context, userID, clientID, provider string, scopes []string, attributes map[string]string, familyID string, resources []string, authDetails []byte, sid string, authCtx oauth.RefreshAuthContext, clientTTLOverride time.Duration) (string, error)
	MaybeEncryptIDToken(ctx context.Context, client *core.Client, signed string) (string, bool)
	SPIFFEValidator() *security.SPIFFEValidator
	SPIFFEAudience() string
	JTIReplayStore() security.JTIReplayStore
	JTIReplayFailClosed() bool
	Auditor() *audit.Recorder
	HandleDeviceSecretExchange(ctx core.HandlerContext, idTokenClaims *core.TokenClaims, rawIDToken, deviceSecret string, client *core.Client, req TokenExchangeRequest)
	RecordTokenIssued(ctx core.HandlerContext, clientID, strategy, subjectID string)
	RecordRefreshTokenIssued(ctx core.HandlerContext, clientID, subjectID string, rotation bool)
	RecordIDTokenIssued(ctx core.HandlerContext, clientID, subjectID string)
	RecordSubjectClientAccess(ctx context.Context, subject, clientID string)
	SrvLogger() spi.Logger
}

// HandleTokenExchangeGrant processes the RFC 8693 token-exchange grant. Behavior
// is byte-identical to the prior root handler.
//
// Oracle-leak collapse (AGENTS.md §3): missing/unsupported subject_token_type →
// invalid_request; subject_token validation failure → invalid_grant; actor_token
// validation/jti-replay failure → invalid_grant; unregistered resource/audience →
// invalid_target; scope expansion → invalid_scope; unsupported
// requested_token_type (and an id_token request with OIDC not configured) →
// invalid_request. RFC 8693 §4.1 act-chain nesting, RFC 9470 step-up, RFC 9396
// authorization_details, and OIDC §8 pairwise subject resolution are preserved.
func HandleTokenExchangeGrant(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, req TokenExchangeRequest) {
	// Stages run in the SAME order as the prior monolith; each emits the exact
	// wire code it did at its gate position (see token_exchange_stages.go). The
	// per-stage collapse codes DIFFER and must NOT drift: invalid_request
	// (pre-flight types), invalid_grant (subject), insufficient_user_authentication
	// (RFC 9470 step-up), invalid_target / invalid_scope (targets+scopes).
	if tokExValidateRequestTypes(d, ctx, client, req) {
		return
	}
	st := &tokExState{}
	if tokExResolveSubject(d, ctx, req, st) {
		return
	}
	if tokExStepUp(ctx, req, st) {
		return
	}
	// Actor resolution: both-or-neither presence, the Native SSO device-secret
	// delegated path (which fully handles + returns), JTI-replay, and the act
	// chain prepend.
	if done, delegated := tokExResolveActor(d, ctx, client, req, st); done || delegated {
		return
	}
	if tokExResolveTargetsAndScopes(d, ctx, client, req, st) {
		return
	}
	if tokExResolveSubjectAndIssue(d, ctx, client, st) {
		return
	}
	tokExAuditSPIFFE(d, ctx, client, st)

	st.resp = map[string]any{
		core.KeyAccessToken:     st.token.AccessToken,
		core.KeyIssuedTokenType: core.TokenTypeAccessToken,
		core.KeyTokenType:       st.token.TokenType,
		core.KeyExpiresIn:       st.token.ExpiresIn,
		core.KeyScope:           st.token.Scope,
		core.KeyTokenStrategy:   st.strategy,
	}
	// Refresh path is FAIL-OPEN (caller keeps the access token on error).
	tokExIssueRefresh(d, ctx, client, req, st)
	// id_token path is FAIL-CLOSED (JWE-required-else-internal-error).
	if tokExIssueIDToken(d, ctx, client, req, st) {
		return
	}

	ctx.JSON(http.StatusOK, st.resp)
}
