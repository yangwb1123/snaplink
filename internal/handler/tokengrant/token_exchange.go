package tokengrant

import (
	"context"
	"net/http"
	"slices"
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
	// DPoPJKT / MTLSX5T are the sender-constraint thumbprints captured from the
	// /token request (RFC 9449 DPoP proof JKT / RFC 8705 mTLS x5t#S256). When a
	// proof/cert was presented, the exchanged access token is cnf-bound to it,
	// exactly as the authorization_code / refresh / CIBA / client_credentials
	// grants do. Empty = no sender-constraint (unbound token, as before).
	DPoPJKT string
	MTLSX5T string
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
	IssueRefreshToken(ctx context.Context, userID, clientID, provider string, scopes []string, attributes map[string]string, familyID string, resources []string, authDetails []byte, sid string, authCtx oauth.RefreshAuthContext, clientTTLOverride time.Duration, confirmationJKT string) (string, error)
	MaybeEncryptIDToken(ctx context.Context, client *core.Client, signed string) (string, bool)
	DPoPTokenTypeOr(defaultType, jkt string) string
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
	st := &tokExState{confJKT: req.DPoPJKT, confX5T: req.MTLSX5T}
	// tokExRefuseNonDelegable rejects a NON-DELEGABLE break-glass subject_token
	// before any mint; short-circuited so st.claims is read only after resolve.
	if tokExResolveSubject(d, ctx, req, st) || tokExRefuseNonDelegable(ctx, st) {
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
		core.KeyTokenType:       d.DPoPTokenTypeOr(st.token.TokenType, req.DPoPJKT),
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

// tokExRefuseNonDelegable refuses to exchange a subject_token that carries the
// break-glass live-impersonation marker. Such a credential is deliberately
// NON-DELEGABLE: exchanging it would mint a fresh token that keeps sub=target but
// (a) escapes the AdminSession revocation cascade (never registered under
// ImpersonationTokens), (b) sheds the act=admin attribution, and (c) takes the
// issuer-default TTL instead of the <=15m grant window. Oracle-safe: collapses to
// the SAME invalid_request the pre-flight type gates emit, revealing nothing about
// the token beyond "this request is not allowed". Returns true when it has written
// a response and the caller must stop — BEFORE any new token is minted.
func tokExRefuseNonDelegable(ctx core.HandlerContext, st *tokExState) bool {
	if core.IsBreakGlassImpersonationClaims(st.claims) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return true
	}
	return false
}

// tokExIssueIDToken mints an id_token when requested_token_type is id_token.
// This path is FAIL-CLOSED: a non-openid scope is invalid_request, and any
// issuer/issuance/JWE-required failure collapses to the internal error. Returns
// true when it has written a response and the caller must stop.
func tokExIssueIDToken(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, req TokenExchangeRequest, st *tokExState) bool {
	// RFC 8693 §2.2.1 id_token output. The access token is always returned. The
	// IDTokenIssuer was confirmed wired up-front (fail-closed invalid_request
	// above), so a resolution failure here is a genuine internal/tenant
	// misconfiguration, NOT a feature-off case.
	//
	// An id_token is only meaningful for an OIDC exchange — one carrying the
	// `openid` scope. A service-to-service exchange (no openid scope; e.g. a
	// SPIFFE SVID) has no user to assert, so demanding an id_token for it is a
	// malformed request → invalid_request (oracle-safe: identical to the
	// unsupported-type collapse).
	if req.RequestedTokenType != core.TokenTypeIDToken {
		return false
	}
	if !slices.Contains(st.scopes, core.ScopeOpenID) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return true
	}
	enc, ok := tokExMintIDToken(d, ctx, client, st)
	if !ok {
		// tokExMintIDToken already wrote the fail-closed internal-error response
		// at whichever sub-gate (issuer resolution / issuance / JWE-required) it
		// failed at.
		return true
	}
	st.resp[core.KeyIDToken] = enc
	// issued_token_type reports the REQUESTED token type (id_token) — what the
	// caller asked the exchange to issue — while the access token is ALSO
	// returned alongside in access_token (RFC 8693 §2.2.1: requested_token_type
	// names what issued_token_type reports, not the exclusive output). The
	// requested id_token is delivered in the dedicated id_token member. This is
	// a deliberate non-exclusive-output design (see TestTokenExchange_IDTokenOutput).
	st.resp[core.KeyIssuedTokenType] = core.TokenTypeIDToken
	d.RecordIDTokenIssued(ctx, client.ID, st.claims.Subject)
	return false
}

// tokExMintIDToken resolves the per-client issuer, mints the id_token, and
// applies per-client JWE. This whole path is FAIL-CLOSED: any issuer-resolution,
// issuance, or JWE-required failure writes the internal error and returns
// ok=false. Returns the (possibly encrypted) id_token on success.
func tokExMintIDToken(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, st *tokExState) (string, bool) {
	idIssuer, _, idErr := d.IDTokenIssuerForClient(client)
	if idErr != nil || idIssuer == nil {
		d.SrvLogger().Error("token exchange id_token issuer resolution failed", "client", client.ID, "error", idErr)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return "", false
	}
	// auth_time / acr / amr / sid propagate from the inbound subject_token
	// exactly as the access token above. AccessToken is the one just minted
	// so the issuer stamps OIDC Core §3.1.3.6 at_hash. No nonce: there is no
	// authorization request in a token-exchange.
	idToken, iErr := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
		Subject:     st.issuedSub,
		Audience:    client.ID,
		AuthTime:    st.claims.AuthTime,
		ACR:         st.claims.ACR,
		AMR:         append([]string(nil), st.claims.AMR...),
		Claims:      st.claims.Extra,
		SID:         st.claims.SID,
		AccessToken: st.token.AccessToken,
	})
	if iErr != nil {
		d.SrvLogger().Error("token exchange id_token issue failed", "client", client.ID, "error", iErr)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return "", false
	}
	// Per-client id_token JWE (OIDC §10.2) when configured — a no-op
	// pass-through when the client has no encrypted-response metadata.
	enc, ok := d.MaybeEncryptIDToken(ctx.Request().Context(), client, idToken)
	if !ok {
		// Encryption requested but no encrypter wired — omitting a requested
		// id_token silently would be a confusing partial success, so collapse
		// to the internal error.
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return "", false
	}
	return enc, true
}
