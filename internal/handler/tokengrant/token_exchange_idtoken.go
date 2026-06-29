package tokengrant

import (
	"net/http"
	"slices"

	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
)

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
