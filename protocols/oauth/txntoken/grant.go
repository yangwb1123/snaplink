package txntoken

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// Request is the subset of /token parameters HandleGrant needs. Pulled out
// of the main /token request struct so the grant reads cleanly — mirrors
// tokengrant.TokenExchangeRequest.
type Request struct {
	SubjectToken     string
	SubjectTokenType string

	// Audience is the RFC 8693 `audience` parameter. RFC 9321 requires
	// EXACTLY one value: the Trust Domain the caller wants a Txn-Token
	// for. Zero or multiple values is invalid_target — a Txn-Token is
	// valid in exactly one trust domain, unlike an ordinary exchanged
	// access token's multi-audience `aud` array.
	Audience []string

	// Purpose is the `purp` request parameter — set fresh on every hop.
	Purpose string

	// RequestContext is the raw `request_context` form/JSON value — a
	// caller-supplied JSON object, or "" for none. Validated as JSON
	// (not merely stored) before being embedded in `rctx`.
	RequestContext string
}

// Deps is what HandleGrant needs from the host server. *sso.Server
// satisfies it via accessors.go.
type Deps interface {
	ValidateAnyToken(ctx context.Context, token string) (*core.TokenClaims, string, error)
	RecordTokenIssued(ctx core.HandlerContext, clientID, strategy, subjectID string)
	SrvLogger() spi.Logger
}

// StrategyName is the `strategy` label recorded via Deps.RecordTokenIssued
// for a Txn-Token mint — distinct from the "jwt"/"session" access-token
// strategies since minting goes through Issuer.Mint, never a
// core.TokenIssuer.
const StrategyName = "txn_token"

// HandleGrant mints a Txn-Token (RFC 9321) from an inbound access token
// or, for a further hop, from a previously-issued Txn-Token presented as
// subject_token. It reuses the RFC 8693 token-exchange grant + /token
// endpoint verbatim — the caller (interfaces/sso) dispatches here ONLY
// when requested_token_type names [TokenType]; every other
// requested_token_type keeps flowing through the ordinary token-exchange
// handler untouched.
//
// Oracle-leak collapse (AGENTS.md §3), mirroring the RFC 8693 grant:
// missing subject_token/subject_token_type or a malformed audience/
// request_context → invalid_request; audience not naming exactly this
// Issuer's Trust Domain → invalid_target; subject_token validation
// failure (of either kind) or an exceeded act-chain depth → invalid_grant.
func HandleGrant(d Deps, issuer *Issuer, validator *Validator, ctx core.HandlerContext, client *core.Client, req Request) {
	if txnValidateRequest(ctx, issuer, req) {
		return
	}
	rctx, ok := txnParseRequestContext(ctx, req)
	if !ok {
		return
	}
	subject, azd, chain, ok := txnResolveSubjectToken(d, validator, ctx, req)
	if !ok {
		return
	}

	signed, claims, err := issuer.Mint(ctx.Request().Context(), MintRequest{
		Subject:              subject,
		RequestingWorkload:   client.ID,
		PriorChain:           chain,
		TrustDomain:          req.Audience[0],
		Purpose:              req.Purpose,
		RequestContext:       rctx,
		AuthorizationDetails: azd,
	})
	if err != nil {
		txnWriteMintError(d, ctx, client, err)
		return
	}

	d.RecordTokenIssued(ctx, client.ID, StrategyName, claims.Sub)
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyAccessToken:     signed,
		core.KeyIssuedTokenType: TokenType,
		core.KeyTokenType:       TokenTypeNameNA,
		core.KeyExpiresIn:       int(claims.Exp - claims.Iat),
	})
}

// txnValidateRequest runs the pre-flight RFC 9321 request-shape checks,
// BEFORE any token is inspected. Returns true when it has already written
// a response and the caller must stop.
func txnValidateRequest(ctx core.HandlerContext, issuer *Issuer, req Request) bool {
	if req.SubjectToken == "" || req.SubjectTokenType == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return true
	}
	if req.SubjectTokenType != core.TokenTypeAccessToken &&
		req.SubjectTokenType != core.TokenTypeJWT &&
		req.SubjectTokenType != TokenType {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return true
	}
	// RFC 9321: `audience` MUST be exactly the Trust Domain name — a
	// Txn-Token is valid in one trust domain, unlike a multi-audience
	// exchanged access token.
	if len(req.Audience) != 1 || req.Audience[0] == "" || req.Audience[0] != issuer.TrustDomain() {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidTarget))
		return true
	}
	return false
}

// txnParseRequestContext validates the caller-supplied `request_context`
// as JSON (if present) — a malformed value is a malformed REQUEST, not a
// credential failure, so it collapses to invalid_request rather than
// invalid_grant. Returns ok=false when it has already written a response.
func txnParseRequestContext(ctx core.HandlerContext, req Request) (json.RawMessage, bool) {
	if req.RequestContext == "" {
		return nil, true
	}
	raw := json.RawMessage(req.RequestContext)
	if !json.Valid(raw) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return nil, false
	}
	return raw, true
}

// txnResolveSubjectToken validates the subject_token — either an ordinary
// access token/JWT (first hop, via Deps.ValidateAnyToken) or a
// previously-issued Txn-Token (nested hop, via validator) — and returns
// the transaction's subject, the RFC 9396 authorization_details to carry
// forward as `azd` (propagated IMMUTABLY on a nested hop), and the prior
// `act` chain to prepend onto. Every failure collapses to invalid_grant
// (oracle-leak hardening, matching the RFC 8693 grant's subject_token
// gate). Returns ok=false when it has already written a response.
func txnResolveSubjectToken(d Deps, validator *Validator, ctx core.HandlerContext, req Request) (subject string, azd json.RawMessage, chain *core.ActorClaim, ok bool) {
	if req.SubjectTokenType == TokenType {
		if validator == nil {
			// The Issuer is wired but no Validator was supplied — nested
			// (chained) minting is unsupported until one is. Collapses to
			// the SAME invalid_grant a validation failure would, so a
			// caller can't distinguish "misconfigured" from "invalid token".
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
			return "", nil, nil, false
		}
		claims, err := validator.Validate(ctx.Request().Context(), req.SubjectToken)
		if err != nil || claims == nil {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
			return "", nil, nil, false
		}
		return claims.Sub, claims.Azd, claims.Act, true
	}

	claims, _, err := d.ValidateAnyToken(ctx.Request().Context(), req.SubjectToken)
	if err != nil || claims == nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return "", nil, nil, false
	}
	return claims.Subject, core.CloneRawJSON(claims.AuthorizationDetails), nil, true
}

// txnWriteMintError maps an Issuer.Mint failure onto its oracle-safe wire
// response: an exceeded act-chain depth is a credential-shaped failure
// (invalid_grant, matching the RFC 8693 grant's own chain-depth gate);
// anything else is a genuine internal/misconfiguration failure.
func txnWriteMintError(d Deps, ctx core.HandlerContext, client *core.Client, err error) {
	if errors.Is(err, ErrChainTooDeep) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return
	}
	d.SrvLogger().Error("txntoken: mint failed", "error", err, "client", client.ID)
	ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
}
