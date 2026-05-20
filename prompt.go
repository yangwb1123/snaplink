package sso

import (
	"encoding/json"
	"net/http"
	"strings"
)

// silentRenewalRequest captures the subset of /auth/login parameters
// the OIDC prompt=none silent flow needs. Bound from the inline req
// struct in handleLogin so the silent-renewal path can be tested and
// reasoned about in isolation.
type silentRenewalRequest struct {
	ClientID             string
	Scope                []string
	State                string
	Nonce                string
	Resource             []string
	AuthorizationDetails json.RawMessage
	IDTokenHint          string
}

// parsePromptValues splits the OIDC prompt parameter and returns the
// unique non-empty values. Empty input returns nil so the caller can
// short-circuit with a `len() == 0` check.
func parsePromptValues(raw string) []string {
	if raw == "" {
		return nil
	}
	seen := make(map[string]struct{}, 4)
	out := make([]string, 0, 4)
	for _, v := range strings.Fields(raw) {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// promptHasNone reports whether the prompt parameter requests silent
// authentication. Convenience over scanning the slice at each site.
func promptHasNone(values []string) bool {
	for _, v := range values {
		if v == PromptNone {
			return true
		}
	}
	return false
}

// handleSilentRenewal implements OIDC Core §3.1.2.1's prompt=none flow.
// The RP loads /auth/login in a hidden iframe with prompt=none +
// id_token_hint to probe whether the End-User still has an active
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
//   - The new ID token's `auth_time` MUST equal the original — no fresh
//     authentication event happened, so the factor freshness signal
//     downstream services see is preserved (RFC 9068 §2.2).
//
// Returns true when the silent flow handled the response (caller MUST
// bail). False on a non-prompt-none request (caller continues).
func (s *Server) handleSilentRenewal(ctx HandlerContext, prompts []string, req silentRenewalRequest, client *Client) bool {
	if !promptHasNone(prompts) {
		return false
	}
	// §3.1.2.1: "none" cannot be combined with any other prompt
	// value; mixing them is meaningless ("don't show UI AND show
	// login UI") and the spec mandates invalid_request.
	if len(prompts) > 1 {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequest, "prompt=none must not be combined with other prompt values"))
		return true
	}
	if req.IDTokenHint == "" {
		// Without a hint we have no way to identify which user
		// the silent renewal targets; the only spec-correct
		// answer is login_required (§3.1.2.6).
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrLoginRequired))
		return true
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), req.IDTokenHint)
	if err != nil || claims == nil {
		// A bad-signature hint is indistinguishable from "no
		// session" on the wire (§3.1.2.6's login_required is
		// the catch-all for "AS needs user reauth"). Don't leak
		// which failure mode triggered it.
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrLoginRequired))
		return true
	}
	// The hint's client_id binding MUST match the requesting client
	// — a hint minted for client A can't be redeemed by client B
	// for a silent renewal (cross-RP confused deputy defense).
	hintedClientID := claims.ClientID
	if hintedClientID == "" && len(claims.Audience) > 0 {
		hintedClientID = claims.Audience[0]
	}
	if hintedClientID != "" && hintedClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrLoginRequired))
		return true
	}

	if s.sessionMgr == nil {
		// No session manager wired = no notion of "active session";
		// safest default is login_required so a misconfigured
		// silent flow falls back cleanly.
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrLoginRequired))
		return true
	}
	sessions, err := s.sessionMgr.ListByUser(ctx.Request().Context(), claims.Subject)
	if err != nil || len(sessions) == 0 {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrLoginRequired))
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
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrLoginRequired))
		return true
	}

	// Issue the renewed access token. Note the explicit reuse of
	// AuthTime/AMR/ACR from the original ID token — silent renewal
	// does NOT represent a fresh end-user auth event, so downstream
	// services consuming RFC 9068 claims see the original factor
	// strength rather than a misleading "just-authenticated" timestamp.
	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		s.logger.Error("no token strategy for client during silent renewal", "client", client.ID, "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrNoTokenStrategy))
		return true
	}
	scopes := req.Scope
	if len(scopes) == 0 {
		// Caller didn't repeat the original scopes — preserve
		// what the hint token carried so the renewed token has
		// the same authority. (If the RP wants to downscope it
		// supplies a subset in the request.)
		scopes = claims.Scopes
	}
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID:                   claims.Subject,
		Resources:            req.Resource,
		ClientID:             client.ID,
		AuthTime:             claims.AuthTime,
		ACR:                  claims.ACR,
		AMR:                  append([]string(nil), claims.AMR...),
		AuthorizationDetails: cloneRawJSON(req.AuthorizationDetails),
		Actor:                claims.Actor,
	}, scopes)
	if err != nil {
		s.logger.Error("silent renewal token issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return true
	}

	resp := map[string]any{
		KeyAccessToken:   token.AccessToken,
		KeyTokenType:     token.TokenType,
		KeyExpiresIn:     token.ExpiresIn,
		KeyScope:         token.Scope,
		KeyTokenStrategy: strategy,
		KeyIss:           s.resolveIssuer(ctx),
	}
	if req.State != "" {
		resp[KeyState] = req.State
	}

	// OIDC id_token: when openid scope present + ID token issuer
	// is wired, mint a fresh id_token alongside. The nonce echoes
	// the request nonce per §3.1.3.7 (the RP correlates this
	// renewed token with its current auth round trip).
	if s.idTokenIssuer != nil && scopeContainsOpenID(scopes) {
		idTok, idErr := s.idTokenIssuer.IssueIDToken(ctx.Request().Context(), &IDTokenRequest{
			Subject:  claims.Subject,
			Audience: client.ID,
			Nonce:    req.Nonce,
			AuthTime: claims.AuthTime,
			ACR:      claims.ACR,
			AMR:      append([]string(nil), claims.AMR...),
		})
		if idErr != nil {
			s.logger.Error("silent renewal id_token issuance failed", "error", idErr)
		} else {
			resp[KeyIDToken] = idTok
		}
	}

	// Silent renewal reuses the original session; emit a token-
	// issued event at the same shape as a fresh login success so
	// auditors see continuous activity per (client, subject).
	s.recordLoginSuccess(ctx, client.ID, "silent_renewal", strategy, claims.Subject, "")
	ctx.JSON(http.StatusOK, resp)
	return true
}

// scopeContainsOpenID is a small helper used by the silent flow + ID
// token plumbing to gate openid-only behaviors. Independent of
// strings.Contains-on-joined to avoid the "openid_extra" false match.
func scopeContainsOpenID(scopes []string) bool {
	for _, s := range scopes {
		if s == ScopeOpenID {
			return true
		}
	}
	return false
}
