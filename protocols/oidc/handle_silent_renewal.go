package oidc

import (
	"context"
	"net/http"
	"time"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// SilentRenewalDeps is what HandleSilentRenewal needs. *sso.Server
// satisfies it via accessor methods.
type SilentRenewalDeps interface {
	SessionMgr() core.SessionManager
	IDTokenIssuer() IDTokenIssuer
	// IDTokenIssuerForClient selects the per-tenant id_token issuer so a
	// tenant's silent-renewal id_token is signed by its own key (same
	// fail-closed discipline as IssuerForClient). emit=false means omit
	// the id_token; err != nil means a misconfigured tenant issuer (also
	// omit). Returns the shared issuer for non-tenant clients.
	IDTokenIssuerForClient(c *core.Client) (IDTokenIssuer, bool, error)
	SrvLogger() spi.Logger
	ValidateAnyToken(ctx context.Context, token string) (*core.TokenClaims, string, error)
	ResolveIssuer(ctx core.HandlerContext) string
	AuthzErrorBody(ctx core.HandlerContext, code string) map[string]string
	AuthzErrorBodyDesc(ctx core.HandlerContext, code, desc string) map[string]string
	IssuerForClient(c *core.Client) (string, core.TokenIssuer, error)
	RecordLoginSuccess(ctx core.HandlerContext, clientID, provider, strategy, userID, sessionID string)

	// EncryptIDTokenForClient applies OIDC ID Token encryption when the
	// client opted in (id_token_encrypted_response_alg set). Returns the
	// value to emit and whether emission is safe; ok=false means fail
	// closed (omit the token rather than leak cleartext). Pass-through
	// (returns signed, true) when the client didn't opt in.
	EncryptIDTokenForClient(ctx context.Context, client *core.Client, signed string) (string, bool)
}

// HandleSilentRenewal implements OIDC Core §3.1.2.1's prompt=none
// flow. The RP loads /auth/login in a hidden iframe with prompt=none
// + id_token_hint to probe whether the End-User still has an active
// session — when yes, a freshly minted access (and id) token returns
// without any UI; when no, error login_required tells the iframe to
// fall back to the visible login flow.
//
// Spec checkpoints satisfied here:
//
//   - §3.1.2.1: prompt=none MUST NOT be combined with other prompt
//     values (caller validated this).
//   - §3.1.2.6: missing or unverifiable id_token_hint → login_required.
//   - §3.1.2.6: no active End-User session → login_required.
//   - §3.1.2.6: hint subject doesn't match the live session → login_required.
//   - The new ID token's auth_time MUST equal the original — no fresh
//     authentication event happened, so the factor freshness signal
//     downstream services see is preserved (RFC 9068 §2.2).
//
// Returns true when the silent flow handled the response (caller
// MUST bail). False on a non-prompt-none request (caller continues).
func HandleSilentRenewal(d SilentRenewalDeps, ctx core.HandlerContext, prompts []string, req SilentRenewalRequest, client *core.Client) bool {
	if !PromptHasNone(prompts) {
		return false
	}
	// §3.1.2.1: "none" cannot be combined with any other prompt
	// value; mixing them is meaningless ("don't show UI AND show
	// login UI") and the spec mandates invalid_request.
	if len(prompts) > 1 {
		ctx.JSON(http.StatusBadRequest, d.AuthzErrorBodyDesc(ctx, core.ErrInvalidRequest, "prompt=none must not be combined with other prompt values"))
		return true
	}
	if req.IDTokenHint == "" {
		// Without a hint we have no way to identify which user the
		// silent renewal targets; the only spec-correct answer is
		// login_required (§3.1.2.6).
		ctx.JSON(http.StatusBadRequest, d.AuthzErrorBody(ctx, core.ErrLoginRequired))
		return true
	}
	claims, _, err := d.ValidateAnyToken(ctx.Request().Context(), req.IDTokenHint)
	if err != nil || claims == nil {
		// A bad-signature hint is indistinguishable from "no session"
		// on the wire (§3.1.2.6's login_required is the catch-all for
		// "AS needs user reauth"). Don't leak which failure mode
		// triggered it.
		ctx.JSON(http.StatusBadRequest, d.AuthzErrorBody(ctx, core.ErrLoginRequired))
		return true
	}
	// The hint's client_id binding MUST match the requesting client
	// — a hint minted for client A can't be redeemed by client B for
	// a silent renewal (cross-RP confused deputy defense).
	hintedClientID := claims.ClientID
	if hintedClientID == "" && len(claims.Audience) > 0 {
		hintedClientID = claims.Audience[0]
	}
	if hintedClientID != "" && hintedClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, d.AuthzErrorBody(ctx, core.ErrLoginRequired))
		return true
	}
	// OIDC Core §3.1.2.1 max_age: when the RP sets it, the AS MUST
	// reauthenticate if the elapsed time since auth_time exceeds the
	// value. prompt=none can't reauthenticate (no UI allowed), so the
	// only spec-correct response is login_required — telling the
	// iframe to fall back to the visible login flow. max_age=0
	// collapses to "always reauthenticate"; nil = no constraint. A
	// zero auth_time means the original token was minted without
	// RFC 9068 claim population — treat as unverifiable freshness
	// and reject the silent renewal.
	if req.MaxAge != nil {
		if claims.AuthTime.IsZero() {
			ctx.JSON(http.StatusBadRequest, d.AuthzErrorBody(ctx, core.ErrLoginRequired))
			return true
		}
		if time.Since(claims.AuthTime) > time.Duration(*req.MaxAge)*time.Second {
			ctx.JSON(http.StatusBadRequest, d.AuthzErrorBody(ctx, core.ErrLoginRequired))
			return true
		}
	}

	sessionMgr := d.SessionMgr()
	if sessionMgr == nil {
		// No session manager wired = no notion of "active session";
		// safest default is login_required so a misconfigured silent
		// flow falls back cleanly.
		ctx.JSON(http.StatusBadRequest, d.AuthzErrorBody(ctx, core.ErrLoginRequired))
		return true
	}
	sessions, err := sessionMgr.ListByUser(ctx.Request().Context(), claims.Subject)
	if err != nil || len(sessions) == 0 {
		ctx.JSON(http.StatusBadRequest, d.AuthzErrorBody(ctx, core.ErrLoginRequired))
		return true
	}
	hasLive := false
	for _, sess := range sessions {
		if sess == nil || sess.Revoked || sess.IsExpired() {
			continue
		}
		hasLive = true
		break
	}
	if !hasLive {
		ctx.JSON(http.StatusBadRequest, d.AuthzErrorBody(ctx, core.ErrLoginRequired))
		return true
	}

	// Issue the renewed access token. Note the explicit reuse of
	// AuthTime/AMR/ACR from the original ID token — silent renewal
	// does NOT represent a fresh end-user auth event, so downstream
	// services consuming RFC 9068 claims see the original factor
	// strength rather than a misleading "just-authenticated" timestamp.
	strategy, ti, err := d.IssuerForClient(client)
	if err != nil {
		d.SrvLogger().Error("no token strategy for client during silent renewal", "client", client.ID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.AuthzErrorBody(ctx, core.ErrNoTokenStrategy))
		return true
	}
	scopes := req.Scope
	if len(scopes) == 0 {
		// Caller didn't repeat the original scopes — preserve what
		// the hint token carried so the renewed token has the same
		// authority. (If the RP wants to downscope it supplies a
		// subset in the request.)
		scopes = claims.Scopes
	}
	token, err := ti.Issue(ctx.Request().Context(), &core.Subject{
		ID:                   claims.Subject,
		Resources:            req.Resource,
		ClientID:             client.ID,
		AuthTime:             claims.AuthTime,
		ACR:                  claims.ACR,
		AMR:                  append([]string(nil), claims.AMR...),
		AuthorizationDetails: core.CloneRawJSON(req.AuthorizationDetails),
		Actor:                claims.Actor,
		// SID stays locked to the hint's session — silent renewal
		// targets the same session the original id_token was minted
		// for, so RPs that bound their local state to the sid see
		// continuity across renewals.
		SID: claims.SID,
		TTL: client.AccessTokenTTL,
	}, scopes)
	if err != nil {
		d.SrvLogger().Error("silent renewal token issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.AuthzErrorBody(ctx, core.ErrInternal))
		return true
	}

	resp := map[string]any{
		core.KeyAccessToken:   token.AccessToken,
		core.KeyTokenType:     token.TokenType,
		core.KeyExpiresIn:     token.ExpiresIn,
		core.KeyScope:         token.Scope,
		core.KeyTokenStrategy: strategy,
		core.KeyIss:           d.ResolveIssuer(ctx),
	}
	if req.State != "" {
		resp[core.KeyState] = req.State
	}

	// OIDC id_token: when openid scope present + ID token issuer is
	// wired, mint a fresh id_token alongside. The nonce echoes the
	// request nonce per §3.1.3.7 (the RP correlates this renewed
	// token with its current auth round trip). The issuer is resolved
	// per-tenant so a tenant's silent-renewal id_token is signed by the
	// same key as its access + login id_tokens (fail closed on a
	// misconfigured/unregistered tenant issuer: omit rather than fall
	// back to the shared key).
	if ScopeContainsOpenID(scopes) {
		idIssuer, emit, resErr := d.IDTokenIssuerForClient(client)
		if resErr != nil {
			d.SrvLogger().Error("silent renewal id_token issuer resolution failed; omitting id_token", "error", resErr, "client", client.ID)
		} else if emit {
			idTok, idErr := idIssuer.IssueIDToken(ctx.Request().Context(), &IDTokenRequest{
				Subject:     claims.Subject,
				Audience:    client.ID,
				Nonce:       req.Nonce,
				AuthTime:    claims.AuthTime,
				ACR:         claims.ACR,
				AMR:         append([]string(nil), claims.AMR...),
				SID:         claims.SID,
				AccessToken: token.AccessToken,
			})
			if idErr != nil {
				d.SrvLogger().Error("silent renewal id_token issuance failed", "error", idErr)
			} else if enc, ok := d.EncryptIDTokenForClient(ctx.Request().Context(), client, idTok); ok {
				resp[core.KeyIDToken] = enc
			}
		}
	}

	// Silent renewal reuses the original session; emit a token-issued
	// event at the same shape as a fresh login success so auditors
	// see continuous activity per (client, subject).
	d.RecordLoginSuccess(ctx, client.ID, "silent_renewal", strategy, claims.Subject, "")
	ctx.JSON(http.StatusOK, resp)
	return true
}
